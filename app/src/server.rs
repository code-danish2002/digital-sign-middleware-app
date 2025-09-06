// src/server.rs
use crate::pdf_signer;
use crate::pin_dialog;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

use hex;
use pkcs11::types;
use pkcs11::Ctx;
use x509_parser::prelude::*;

use rfd;

// ---- Data structures ----

#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureArea {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub page: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command")]
enum Command {
    GetCertificates,
    SignAndEmbed {
        pdf_data: String,
        slot_id: u64,
        cka_id: String,
        signature_area: SignatureArea,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "command")]
enum Response {
    Certificates {
        status: String,
        certificates: Vec<CertificateInfo>,
    },
    Signature {
        status: String,
        signed_pdf_data: String,
    },
    Error {
        status: String,
        message: String,
    },
}

#[derive(Debug, Serialize)]
struct CertificateInfo {
    id: u64,
    slot_id: u64,
    label: String,
    subject: String,
    cka_id: String,
}

// ---- PKCS#11 helpers ----

fn get_pkcs11_context() -> Result<Arc<Ctx>> {
    let path = r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\wdpkcs.dll";
    let ctx = Ctx::new_and_initialize(path)
        .map_err(|e| anyhow!("Failed to initialize PKCS#11 context: {}", e))?;
    Ok(Arc::new(ctx))
}

async fn get_available_certificates(pkcs11_ctx: Arc<Ctx>) -> Result<Vec<CertificateInfo>> {
    let mut certs = Vec::new();
    println!("--- Starting certificate scan ---");

    let slot_ids = pkcs11_ctx
        .get_slot_list(true)
        .map_err(|e| anyhow!("Failed to get slot list: {}", e))?;

    println!("Found {} slots with tokens.", slot_ids.len());

    if slot_ids.is_empty() {
        println!("No tokens detected. Please insert a smart card or USB token.");
    }

    for slot_id in slot_ids {
        println!("Scanning slot ID: {}", slot_id);

        let flags = types::CKF_SERIAL_SESSION;
        let session = pkcs11_ctx
            .open_session(slot_id, flags, None, None)
            .map_err(|e| anyhow!("open_session failed for slot {}: {}", slot_id, e))?;

        let cert_class_val: types::CK_ULONG = types::CKO_CERTIFICATE as types::CK_ULONG;
        let template = [types::CK_ATTRIBUTE::new(types::CKA_CLASS).with_ck_ulong(&cert_class_val)];

        pkcs11_ctx
            .find_objects_init(session, &template)
            .map_err(|e| anyhow!("find_objects_init failed: {}", e))?;

        let objects = pkcs11_ctx
            .find_objects(session, 64)
            .map_err(|e| anyhow!("find_objects failed: {}", e))?;

        println!(
            "Found {} certificate objects in slot {}.",
            objects.len(),
            slot_id
        );

        for obj in objects {
            let mut attr_types = vec![
                types::CK_ATTRIBUTE::new(types::CKA_LABEL),
                types::CK_ATTRIBUTE::new(types::CKA_ID),
                types::CK_ATTRIBUTE::new(types::CKA_VALUE),
            ];

            let result = pkcs11_ctx.get_attribute_value(session, obj, &mut attr_types);
            if let Err(e) = result {
                println!(
                    "Warning: Failed to get attribute sizes for object {}: {}",
                    obj, e
                );
                continue;
            }

            let label_len = attr_types[0].ulValueLen;
            let id_len = attr_types[1].ulValueLen;
            let value_len = attr_types[2].ulValueLen;

            if value_len == types::CK_UNAVAILABLE_INFORMATION {
                println!("Warning: Unavailable certificate value for object {}", obj);
                continue;
            }

            let mut label_buf = if label_len != types::CK_UNAVAILABLE_INFORMATION && label_len > 0 {
                vec![0u8; label_len as usize]
            } else {
                vec![]
            };

            let mut id_buf = if id_len != types::CK_UNAVAILABLE_INFORMATION && id_len > 0 {
                vec![0u8; id_len as usize]
            } else {
                vec![]
            };

            let mut value_buf = vec![0u8; value_len as usize];

            let mut attrs = Vec::new();

            if !label_buf.is_empty() {
                attrs.push(types::CK_ATTRIBUTE::new(types::CKA_LABEL).with_bytes(&mut label_buf));
            }

            if !id_buf.is_empty() {
                attrs.push(types::CK_ATTRIBUTE::new(types::CKA_ID).with_bytes(&mut id_buf));
            }

            attrs.push(types::CK_ATTRIBUTE::new(types::CKA_VALUE).with_bytes(&mut value_buf));

            let result = pkcs11_ctx.get_attribute_value(session, obj, &mut attrs);
            if let Err(e) = result {
                println!(
                    "Warning: Failed to get attribute values for object {}: {}",
                    obj, e
                );
                continue;
            }

            let label = if !label_buf.is_empty() {
                String::from_utf8_lossy(&label_buf)
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                "No Label".to_string()
            };

            let cert_der = value_buf.clone();

            let subject_str = if !cert_der.is_empty() {
                match X509Certificate::from_der(&cert_der) {
                    Ok((_, cert)) => cert.subject().to_string(),
                    Err(e) => {
                        println!("Warning: Failed to parse certificate subject: {}", e);
                        "Failed to parse subject".to_string()
                    }
                }
            } else {
                "No Certificate DER Found".to_string()
            };

            let cka_id_hex = if !id_buf.is_empty() {
                hex::encode(&id_buf)
            } else {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};

                let mut hasher = DefaultHasher::new();
                label.hash(&mut hasher);
                subject_str.hash(&mut hasher);
                format!("{:x}", hasher.finish())
            };

            let id_u64 = obj as u64;

            println!(
                "   - Detected Certificate: Label='{}', Subject='{}', ID='{}', CKA_ID='{}'",
                label, subject_str, id_u64, cka_id_hex
            );

            certs.push(CertificateInfo {
                id: id_u64,
                slot_id: slot_id as u64,
                label,
                subject: subject_str,
                cka_id: cka_id_hex,
            });
        }

        pkcs11_ctx
            .find_objects_final(session)
            .map_err(|e| anyhow!("find_objects_final failed: {}", e))?;

        pkcs11_ctx
            .close_session(session)
            .map_err(|e| anyhow!("close_session failed: {}", e))?;
    }

    println!("--- Certificate scan finished ---");

    Ok(certs)
}

// In your src/server.rs, update the sign_hash function:

pub async fn sign_hash(
    pkcs11_ctx: Arc<Ctx>,
    slot_id: u64,
    cka_id: &str,
    hash_bytes: &[u8],
    app_handle: tauri::AppHandle,
) -> Result<(Vec<u8>, Vec<u8>)> {
    println!("Please enter the PIN for token in slot {}:", slot_id);

    // Use GUI PIN dialog instead of console input
    let prompt = format!("Enter PIN for token in slot {}", slot_id);
    println!("Showing PIN dialog with prompt: {}", prompt);
    
    let pin_result = pin_dialog::show_pin_dialog(&app_handle, prompt).await;
    println!("PIN dialog returned result");
    
    let pin = match pin_result {
        Ok(pin) => {
            if pin.is_empty() {
                println!("PIN entry was cancelled by user");
                return Err(anyhow!("PIN entry cancelled"));
            }
            println!("PIN received successfully (length: {} characters)", pin.len());
            pin
        }
        Err(e) => {
            println!("PIN dialog error: {}", e);
            return Err(anyhow!("PIN dialog error: {}", e));
        }
    };

    println!("Opening session for slot {}", slot_id);
    let flags = types::CKF_SERIAL_SESSION | types::CKF_RW_SESSION;
    let session = pkcs11_ctx
        .open_session(slot_id as types::CK_SLOT_ID, flags, None, None)
        .map_err(|e| anyhow!("Failed to open session: {}", e))?;

    println!("Attempting to login with provided PIN");
    let login_result = pkcs11_ctx
        .login(session, types::CKU_USER, Some(&pin));
    
    match login_result {
        Ok(_) => println!("Successfully logged in to token"),
        Err(e) => {
            println!("Login failed: {}", e);
            // Clean up session before returning error
            let _ = pkcs11_ctx.close_session(session);
            return Err(anyhow!("Failed to login: {}", e));
        }
    }

    let cert_id_bytes = match hex::decode(cka_id) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            return Err(anyhow!("Invalid CKA_ID format: must be hex string"));
        }
    };

    // Rest of your function remains the same...
    let key_class_val: types::CK_ULONG = types::CKO_PRIVATE_KEY as types::CK_ULONG;
    let key_template = vec![
        types::CK_ATTRIBUTE::new(types::CKA_CLASS).with_ck_ulong(&key_class_val),
        types::CK_ATTRIBUTE::new(types::CKA_ID).with_bytes(&cert_id_bytes),
    ];

    pkcs11_ctx
        .find_objects_init(session, &key_template)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects_init (keys) failed: {}", e)
        })?;

    let key_objs = pkcs11_ctx
        .find_objects(session, 4)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects (keys) failed: {}", e)
        })?;

    pkcs11_ctx
        .find_objects_final(session)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects_final (keys) failed: {}", e)
        })?;

    let key_handle = *key_objs
        .get(0)
        .context("Private key not found for the given CKA_ID")?;

    let mech = types::CK_MECHANISM {
        mechanism: types::CKM_SHA256_RSA_PKCS,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    pkcs11_ctx
        .sign_init(session, &mech, key_handle)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("sign_init failed: {}", e)
        })?;

    let signature = pkcs11_ctx
        .sign(session, &hash_bytes)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("sign failed: {}", e)
        })?;

    let cert_class_val: types::CK_ULONG = types::CKO_CERTIFICATE as types::CK_ULONG;
    let cert_template = vec![
        types::CK_ATTRIBUTE::new(types::CKA_CLASS).with_ck_ulong(&cert_class_val),
        types::CK_ATTRIBUTE::new(types::CKA_ID).with_bytes(&cert_id_bytes),
    ];

    pkcs11_ctx
        .find_objects_init(session, &cert_template)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects_init (cert by ID) failed: {}", e)
        })?;

    let cert_objects = pkcs11_ctx
        .find_objects(session, 1)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects (cert by ID) failed: {}", e)
        })?;

    pkcs11_ctx
        .find_objects_final(session)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("find_objects_final (cert by ID) failed: {}", e)
        })?;

    let cert_obj = *cert_objects
        .get(0)
        .context("Certificate not found for the given CKA_ID")?;

    let mut cert_value_attr_types = vec![types::CK_ATTRIBUTE::new(types::CKA_VALUE)];
    pkcs11_ctx
        .get_attribute_value(session, cert_obj, &mut cert_value_attr_types)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("Failed to get cert CKA_VALUE size: {}", e)
        })?;

    let cert_value_len = cert_value_attr_types[0].ulValueLen;
    if cert_value_len == types::CK_UNAVAILABLE_INFORMATION {
        let _ = pkcs11_ctx.logout(session);
        let _ = pkcs11_ctx.close_session(session);
        return Err(anyhow!("Certificate value not available"));
    }

    let mut cert_value_buf = vec![0u8; cert_value_len as usize];
    let mut cert_attrs =
        vec![types::CK_ATTRIBUTE::new(types::CKA_VALUE).with_bytes(&mut cert_value_buf)];
    pkcs11_ctx
        .get_attribute_value(session, cert_obj, &mut cert_attrs)
        .map_err(|e| {
            let _ = pkcs11_ctx.logout(session);
            let _ = pkcs11_ctx.close_session(session);
            anyhow!("get_attribute_value(cert CKA_VALUE) failed: {}", e)
        })?;

    let cert_der = cert_value_buf;

    // Proper cleanup
    let _ = pkcs11_ctx.logout(session);
    let _ = pkcs11_ctx.close_session(session);

    println!("Successfully completed sign_hash operation");
    Ok((signature, cert_der))
}

async fn handle_sign_and_embed(
    pkcs11_ctx: Arc<Ctx>,
    pdf_data: String,
    slot_id: u64,
    cka_id: String,
    signature_area: SignatureArea,
    app_handle: tauri::AppHandle,
) -> Result<Response> {
    println!("=== STARTING PDF SIGNING PROCESS ===");
    println!("PDF data length: {} characters", pdf_data.len());
    println!("Slot ID: {}", slot_id);
    println!("CKA ID: {}", cka_id);
    println!("Signature area: {:?}", signature_area);

    let pdf_bytes = general_purpose::STANDARD
        .decode(&pdf_data)
        .context("Failed to decode PDF base64")?;

    println!("PDF decoded successfully, size: {} bytes", pdf_bytes.len());

    // Call the function from the new module
    let signed_pdf_bytes = pdf_signer::sign_and_embed_pdf(
        pkcs11_ctx,
        &pdf_bytes,
        slot_id,
        &cka_id,
        &signature_area,
        app_handle,
    )
    .await?;

    let signed_pdf_b64 = general_purpose::STANDARD.encode(&signed_pdf_bytes);

    show_success_dialog("Success", "Document signed successfully!").ok();

    println!("=== SENDING SIGNED PDF RESPONSE ===");
    println!("Response status: success");
    println!("Response data length: {} characters", signed_pdf_b64.len());
    Ok(Response::Signature {
        status: "success".to_string(),
        signed_pdf_data: signed_pdf_b64,
    })
}

async fn handle_connection(
    pkcs11_ctx: Arc<Ctx>,
    raw_stream: TcpStream,
    app_handle: tauri::AppHandle,
) {
    let ws_stream = match tokio_tungstenite::accept_async(raw_stream).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Error accepting WebSocket connection: {}", e);
            return;
        }
    };
    println!("WebSocket connection established.");

    let (mut tx, mut rx) = ws_stream.split();

    while let Some(msg) = rx.next().await {
        let msg = match msg {
            Ok(Message::Text(s)) => s,
            Ok(Message::Binary(_)) => {
                let err_msg = "Binary messages are not supported.".to_string();
                let _ = tx
                    .send(Message::Text(
                        serde_json::to_string(&Response::Error {
                            status: "error".to_string(),
                            message: err_msg.clone(),
                        })
                        .unwrap(),
                    ))
                    .await;
                continue;
            }
            Ok(Message::Close(_)) => {
                println!("Client disconnected.");
                break;
            }
            Ok(_) => continue,
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                break;
            }
        };

        let result = match serde_json::from_str::<Command>(&msg) {
            Ok(Command::GetCertificates) => get_available_certificates(pkcs11_ctx.clone())
                .await
                .map(|certs| Response::Certificates {
                    status: "success".to_string(),
                    certificates: certs,
                }),
            Ok(Command::SignAndEmbed {
                pdf_data,
                slot_id,
                cka_id,
                signature_area,
            }) => {
                handle_sign_and_embed(
                    pkcs11_ctx.clone(),
                    pdf_data,
                    slot_id,
                    cka_id,
                    signature_area,
                    app_handle.clone(),
                )
                .await
            }
            Err(e) => {
                let err_msg = format!("Invalid command format: {}", e);
                eprintln!("{}", err_msg);
                Err(anyhow!(err_msg))
            }
        };

        let response = match result {
            Ok(res) => res,
            Err(e) => Response::Error {
                status: "error".to_string(),
                message: format!("{}", e),
            },
        };

        let response_str = serde_json::to_string(&response).unwrap();
        if let Err(e) = tx.send(Message::Text(response_str)).await {
            eprintln!("Error sending response: {}", e);
            break;
        }
    }
}

// Show success dialog
fn show_success_dialog(title: &str, message: &str) -> Result<()> {
    rfd::MessageDialog::new()
        .set_title(title)
        .set_description(message)
        .set_level(rfd::MessageLevel::Info)
        .show();
    Ok(())
}

// ---- main ----

pub async fn start(app_handle: tauri::AppHandle) -> Result<()> {
    println!("Digital signing server starting...");
    let pkcs11_ctx = get_pkcs11_context()
        .context("Failed to initialize PKCS#11 context. Ensure the DLL/SO path is correct.")?;

    let addr = "127.0.0.1:8999";
    let listener = TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address. Is another instance running?")?;
    println!("Local digital signature service started at: ws://{}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        let pkcs11_ctx_clone = pkcs11_ctx.clone();
        let app_handle_clone = app_handle.clone();
        tokio::spawn(async move {
            handle_connection(pkcs11_ctx_clone, stream, app_handle_clone).await;
        });
    }

    Ok(())
}
