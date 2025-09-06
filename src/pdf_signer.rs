use crate::{SignatureArea, sign_hash};
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use lopdf::{Document, Object, dictionary, content::Content};
use pkcs11::Ctx;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::Arc;
use x509_parser::prelude::*;

// Windows-specific imports
#[cfg(windows)]
use winapi::um::wincrypt::*;
#[cfg(windows)]
use winapi::um::winbase::*;
#[cfg(windows)]
use winapi::um::minwinbase::*;
#[cfg(windows)]
use winapi::shared::minwindef::*;
#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use std::mem;
#[cfg(windows)]
use std::slice;

pub async fn sign_and_embed_pdf(
    pkcs11_ctx: Arc<Ctx>,
    pdf_bytes: &[u8],
    slot_id: u64,
    cka_id: &str,
    sig_area: &SignatureArea,
) -> Result<Vec<u8>> {
    println!("--- Starting PDF Signing and Embedding ---");

    // Load the document
    let mut doc = Document::load_from(Cursor::new(pdf_bytes))
        .context("Failed to parse PDF document")?;

    let sig_dict_id = doc.new_object_id();
    let sig_field_id = doc.new_object_id();

    // Reserve space for signature (placeholder)
    let placeholder_size = 65_536; // 64KB should be enough for signatures with full chain
    let placeholder = "A".repeat(placeholder_size);

    // Create signature dictionary
    let mut sig_dict = lopdf::Dictionary::new();
    sig_dict.set("Type", "Sig");
    sig_dict.set("Filter", "Adobe.PPKLite");
    sig_dict.set("SubFilter", "adbe.pkcs7.detached");
    sig_dict.set("M", Object::string_literal(Utc::now().to_rfc3339()));
    sig_dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );
    sig_dict.set("Contents", Object::string_literal(placeholder.as_str()));
    doc.objects.insert(sig_dict_id, Object::Dictionary(sig_dict));

    // ===== CREATE APPEARANCE STREAM =====
    // Get certificate for subject info
    let (_, certificate_der) = sign_hash(pkcs11_ctx.clone(), slot_id, cka_id, &[0u8; 32])
        .await
        .context("Failed to get certificate for appearance")?;

    let (_, cert) = X509Certificate::from_der(&certificate_der)
        .map_err(|e| anyhow!("Certificate parse error: {}", e))?;
    let subject = cert.tbs_certificate.subject.to_string();
    let formatted_subject = format_subject(&subject);

    // Create appearance content with proper positioning
    let mut content_operations = Vec::new();

    // Begin text object
    content_operations.push(lopdf::content::Operation {
        operator: "BT".into(),
        operands: vec![],
    });

    // Set font and size
    content_operations.push(lopdf::content::Operation {
        operator: "Tf".into(),
        operands: vec![
            Object::Name("Helv".into()),
            Object::Integer(8), // Smaller font to prevent overflow
        ],
    });

    // Starting position (with margins)
    let margin = 5.0;
    content_operations.push(lopdf::content::Operation {
        operator: "Td".into(),
        operands: vec![
            Object::Real(margin as f32),
            Object::Real((sig_area.height - 12.0) as f32), // Start from top
        ],
    });

    // Add signature info lines
    let date_line = format!("Date: {}", Utc::now().format("%Y.%m.%d %H:%M:%S"));
    let lines = vec![
        "Digitally signed by".to_string(),
        formatted_subject.clone(),
        date_line,
    ];

    for (i, line) in lines.iter().enumerate() {
        // Move to next line position
        if i > 0 {
            content_operations.push(lopdf::content::Operation {
                operator: "Td".into(),
                operands: vec![
                    Object::Real(0.0),
                    Object::Real(-10.0), // Line spacing
                ],
            });
        }

        // Draw the text
        content_operations.push(lopdf::content::Operation {
            operator: "Tj".into(),
            operands: vec![Object::string_literal(line.as_str())],
        });
    }

    // End text object
    content_operations.push(lopdf::content::Operation {
        operator: "ET".into(),
        operands: vec![],
    });

    // Font object
    let font_id = doc.new_object_id();
    doc.objects.insert(
        font_id,
        Object::Dictionary(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
            "Encoding" => "WinAnsiEncoding"
        }),
    );

    // Appearance stream dictionary
    let bbox = vec![
        Object::Integer(0),
        Object::Integer(0),
        Object::Integer(sig_area.width as i64),
        Object::Integer(sig_area.height as i64),
    ];

    let appearance_stream_dict = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Form",
        "BBox" => Object::Array(bbox),
        "Matrix" => Object::Array(vec![
            Object::Real(1.0),
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(1.0),
            Object::Real(0.0),
            Object::Real(0.0),
        ]),
        "Resources" => dictionary! {
            "Font" => dictionary! {
                "Helv" => Object::Reference(font_id)
            }
        }
    };

    let content = Content {
        operations: content_operations,
    };

    let stream_dict = lopdf::Dictionary::from(appearance_stream_dict);
    let stream = lopdf::Stream::new(stream_dict, content.encode().unwrap());
    let appearance_id = doc.new_object_id();
    doc.objects.insert(appearance_id, Object::Stream(stream));

    // ===== PAGE COORDINATES =====
    let pages = doc.get_pages();
    let page_ref = pages
        .get(&(sig_area.page as u32))
        .context("Invalid page number")?;

    let page_obj = doc.objects.get(page_ref).context("Page object not found")?;
    let page_dict = match page_obj {
        Object::Dictionary(dict) => dict,
        _ => return Err(anyhow!("Page object is not a dictionary")),
    };

    let media_box = page_dict
        .get(b"MediaBox")
        .context("MediaBox not found in page dictionary")?
        .as_array()
        .context("MediaBox is not an array")?;

    let page_height = match media_box.get(3) {
        Some(Object::Real(h)) => *h as f64,
        Some(Object::Integer(h)) => *h as f64,
        _ => return Err(anyhow!("Invalid MediaBox format")),
    };

    // Convert to PDF coordinate system (bottom-left origin)
    let pdf_y_bottom = page_height - (sig_area.y + sig_area.height);
    let pdf_y_top = page_height - sig_area.y;

    // Create signature field annotation
    let sig_field_dict = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "Rect" => Object::Array(vec![
            Object::Real(sig_area.x as f32),
            Object::Real(pdf_y_bottom as f32),
            Object::Real((sig_area.x + sig_area.width) as f32),
            Object::Real(pdf_y_top as f32)
        ]),
        "F" => 132, // Visible, printable
        "FT" => "Sig",
        "V" => Object::Reference(sig_dict_id),
        "T" => Object::string_literal("Signature1"),
        "Name" => Object::string_literal("Signature"),
        "AP" => dictionary! {
            "N" => Object::Reference(appearance_id)
        }
    };

    doc.objects.insert(sig_field_id, Object::Dictionary(sig_field_dict));

    // Add annotation to page
    let page_dict_mut = doc
        .objects
        .get_mut(page_ref)
        .context("Page object not found")?
        .as_dict_mut()
        .context("Page object is not a dictionary")?;

    if !page_dict_mut.has(b"Annots") {
        page_dict_mut.set(b"Annots", Object::Array(vec![]));
    }
    let annots = page_dict_mut.get_mut(b"Annots")?.as_array_mut()?;
    annots.push(Object::Reference(sig_field_id));

    // ===== UPDATE ACROFORM =====
    let catalog_id = doc.trailer.get(b"Root")
        .map_err(|_| anyhow!("Root not found"))?
        .as_reference()
        .map_err(|_| anyhow!("Root is not a reference"))?;

    let catalog_dict = doc.objects.get(&catalog_id)
        .ok_or_else(|| anyhow!("Catalog object not found"))?
        .as_dict()
        .map_err(|_| anyhow!("Catalog is not a dictionary"))?;

    if !catalog_dict.has(b"AcroForm") {
        let acro_form_id = doc.new_object_id();
        let acro_form_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(sig_field_id)]),
            "SigFlags" => 3
        };
        doc.objects.insert(acro_form_id, Object::Dictionary(acro_form_dict));
        let catalog_dict_mut = doc.objects.get_mut(&catalog_id)
            .unwrap()
            .as_dict_mut()
            .unwrap();
        catalog_dict_mut.set(b"AcroForm", Object::Reference(acro_form_id));
    } else {
        let acro_form_ref = catalog_dict.get(b"AcroForm")
            .map_err(|_| anyhow!("AcroForm not found"))?
            .as_reference()
            .map_err(|_| anyhow!("AcroForm is not a reference"))?;

        let acro_form_dict = doc.objects.get_mut(&acro_form_ref)
            .ok_or_else(|| anyhow!("AcroForm object not found"))?
            .as_dict_mut()
            .map_err(|_| anyhow!("AcroForm is not a dictionary"))?;

        if acro_form_dict.has(b"Fields") {
            let fields = acro_form_dict.get_mut(b"Fields")?.as_array_mut()?;
            fields.push(Object::Reference(sig_field_id));
        } else {
            acro_form_dict.set(b"Fields", Object::Array(vec![Object::Reference(sig_field_id)]));
        }
        acro_form_dict.set(b"SigFlags", 3);
    }

    // ===== FIRST SAVE: GET BYTERANGE =====
    let mut temp_buffer = Cursor::new(Vec::new());
    doc.save_to(&mut temp_buffer)?;
    let temp_bytes = temp_buffer.into_inner();

    let placeholder_start = temp_bytes
        .windows(placeholder.len())
        .position(|w| w == placeholder.as_bytes())
        .context("Placeholder not found in PDF")?;

    let byte_range = vec![
        0,
        placeholder_start as i64,
        (placeholder_start + placeholder.len()) as i64,
        (temp_bytes.len() - placeholder_start - placeholder.len()) as i64,
    ];

    // Update ByteRange in signature dictionary
    let sig_dict = doc.objects.get_mut(&sig_dict_id)
        .context("Signature dictionary not found")?
        .as_dict_mut()
        .context("Signature object is not a dictionary")?;

    sig_dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(byte_range[0]),
            Object::Integer(byte_range[1]),
            Object::Integer(byte_range[2]),
            Object::Integer(byte_range[3]),
        ]),
    );

    // ===== HASH THE BYTE RANGE =====
    let mut hasher = Sha256::new();
    hasher.update(&temp_bytes[0..byte_range[1] as usize]);
    hasher.update(&temp_bytes[byte_range[2] as usize..]);
    let doc_hash = hasher.finalize().to_vec();

    // ===== CREATE SIGNED ATTRIBUTES =====
    let signed_attrs = create_signed_attributes(&doc_hash, &certificate_der)
        .context("Failed to create signed attributes")?;

    let mut attrs_hasher = Sha256::new();
    attrs_hasher.update(&signed_attrs);
    let attrs_hash = attrs_hasher.finalize().to_vec();

    // ===== SIGN HASH =====
    let (signature, certificate_der) = sign_hash(pkcs11_ctx, slot_id, cka_id, &attrs_hash)
        .await
        .context("Failed to sign hash")?;

    // ===== CREATE CMS =====
    let pkcs7_container = create_cms(&signature, &certificate_der, &signed_attrs)
        .context("Failed to create CMS container")?;

    // ===== FINAL: UPDATE CONTENTS WITH HEX SIGNATURE =====
    let sig_hex = hex::encode(&pkcs7_container).to_uppercase();

    // Ensure signature fits in placeholder
    if sig_hex.len() > placeholder_size {
        return Err(anyhow!(
            "Signature too large: {} bytes, max allowed: {}",
            sig_hex.len(),
            placeholder_size
        ));
    }

    let sig_padded = format!("{}", sig_hex);
    let padding_needed = placeholder_size - sig_padded.len();
    let padded_signature = if padding_needed > 0 {
        format!("{}{}", sig_padded, " ".repeat(padding_needed))
    } else {
        sig_padded
    };

    let sig_dict = doc.objects.get_mut(&sig_dict_id)
        .context("Signature dictionary not found")?
        .as_dict_mut()
        .context("Signature object is not a dictionary")?;

    *sig_dict.get_mut(b"Contents").unwrap() = Object::string_literal(padded_signature.as_str());

    // ===== FINAL SAVE =====
    let mut final_buffer = Cursor::new(Vec::new());
    doc.save_to(&mut final_buffer)?;
    let final_bytes = final_buffer.into_inner();

    println!("--- PDF Signing and Embedding Finished ---");
    Ok(final_bytes)
}

fn format_subject(subject: &str) -> String {
    if let Some(cn_start) = subject.find("CN=") {
        let cn = &subject[cn_start + 3..];
        if let Some(end) = cn.find(',') {
            cn[..end].trim().to_string()
        } else {
            cn.trim().to_string()
        }
    } else {
        subject.split('/').last().unwrap_or("").trim().to_string()
    }
}

#[cfg(windows)]
fn get_certificate_chain_from_store(cert_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    unsafe {
        // Create certificate context from DER
        let cert_context = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            cert_der.as_ptr(),
            cert_der.len() as u32,
        );
        
        if cert_context.is_null() {
            return Err(anyhow!("Failed to create certificate context"));
        }

        // Build certificate chain
        let chain_engine = ptr::null_mut();
        let mut chain_para: CERT_CHAIN_PARA = mem::zeroed();
        chain_para.cbSize = mem::size_of::<CERT_CHAIN_PARA>() as u32;
        
        let mut chain_context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
        
        let result = CertGetCertificateChain(
            chain_engine,
            cert_context,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut chain_para,
            0,
            ptr::null_mut(),
            &mut chain_context as *mut _ as *mut *const CERT_CHAIN_CONTEXT,
        );

        if result == 0 || chain_context.is_null() {
            CertFreeCertificateContext(cert_context);
            return Err(anyhow!("Failed to build certificate chain"));
        }

        // Extract certificates from chain
        let mut chain = Vec::new();
        
        let chain_context_ref = &*chain_context;
        if chain_context_ref.cChain > 0 {
            let chains = slice::from_raw_parts(
                chain_context_ref.rgpChain,
                chain_context_ref.cChain as usize,
            );
            
            if !chains.is_empty() {
                let simple_chain = &*chains[0];
                let elements = slice::from_raw_parts(
                    simple_chain.rgpElement,
                    simple_chain.cElement as usize,
                );
                
                // Add certificates in order (leaf first, then issuers)
                for element in elements {
                    let element_ref = &**element;
                    let cert_ctx = element_ref.pCertContext;
                    if !cert_ctx.is_null() {
                        let cert_blob = (*cert_ctx).pbCertEncoded;
                        let cert_len = (*cert_ctx).cbCertEncoded;
                        
                        let cert_der = slice::from_raw_parts(cert_blob, cert_len as usize).to_vec();
                        chain.push(cert_der);
                    }
                }
            }
        }

        // Cleanup
        CertFreeCertificateChain(chain_context);
        CertFreeCertificateContext(cert_context);

        if chain.is_empty() {
            // Fallback: just return the leaf certificate
            Ok(vec![cert_der.to_vec()])
        } else {
            Ok(chain)
        }
    }
}

#[cfg(not(windows))]
fn get_certificate_chain_from_store(cert_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Fallback for non-Windows platforms - just return the leaf certificate
    Ok(vec![cert_der.to_vec()])
}

fn create_signed_attributes(doc_hash: &[u8], certificate_der: &[u8]) -> Result<Vec<u8>> {
    let content_type_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 1]);
    let message_digest_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 4]);
    let signing_time_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 5]);
    let reason_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 16, 3, 1]);
    let location_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 16, 3, 2]);
    let signing_cert_v2_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 16, 3, 10]);

    let now = Utc::now();

    let der = yasna::construct_der(|writer| {
        writer.write_set(|writer| {
            // Content Type
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&content_type_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_oid(&content_type_oid);
                });
            });

            // Message Digest
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&message_digest_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_bytes(doc_hash);
                });
            });

            // Signing Time
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&signing_time_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_ia5_string(&now.to_rfc3339());
                });
            });

            // Reason
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&reason_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_utf8_string("I agree to the terms of this document");
                });
            });

            // Location
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&location_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_utf8_string("India");
                });
            });

            // Signing Certificate V2
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&signing_cert_v2_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_der(certificate_der);
                    });
                });
            });
        })
    });

    Ok(der)
}

fn create_cms(signature: &[u8], certificate: &[u8], signed_attrs_der: &[u8]) -> Result<Vec<u8>> {
    // Get full certificate chain using Windows CryptoAPI
    let chain = get_certificate_chain_from_store(certificate)
        .map_err(|e| anyhow!("Failed to build certificate chain: {}", e))?;

    let (_, cert) = X509Certificate::from_der(certificate)?;

    // Properly encode the issuer and serial number
    let issuer_der = cert.tbs_certificate.issuer.as_raw();
    let serial_bigint = &cert.tbs_certificate.serial;
    let serial_bytes = serial_bigint.to_bytes_be();
    
    // Ensure the serial number is properly formatted (prepend 0x00 if negative)
    let serial_der = if !serial_bytes.is_empty() && (serial_bytes[0] & 0x80) != 0 {
        let mut v = vec![0x00];
        v.extend_from_slice(&serial_bytes);
        v
    } else {
        serial_bytes
    };
    
    let signed_data_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 2]);
    let data_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 1]);
    let sha256_oid = yasna::models::ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    let rsa_encryption_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]);

    let cms = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&signed_data_oid);
            writer.next().write_tagged_implicit(yasna::Tag::context(0), |writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_u8(1); // version

                    // Digest algorithms
                    writer.next().write_sequence(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&sha256_oid);
                            writer.next().write_null();
                        });
                    });

                    // Encapsulated content info
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&data_oid);
                        // Note: Not including eContent for detached signatures
                    });

                    // Certificates
                    writer.next().write_tagged_implicit(yasna::Tag::context(0), |writer| {
                        writer.write_sequence(|writer| {
                            for cert_der in &chain {
                                writer.next().write_der(cert_der);
                            }
                        });
                    });

                    // Signer info
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_u8(1); // version

                            // SignerIdentifier (IssuerAndSerialNumber)
                            writer.next().write_sequence(|writer| {
                                writer.next().write_der(issuer_der);
                                // Write serial number directly as DER-encoded INTEGER
                                writer.next().write_der(&serial_der);
                            });

                            // Digest algorithm
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&sha256_oid);
                                writer.next().write_null();
                            });

                            // Signed attributes
                            writer.next().write_tagged_implicit(yasna::Tag::context(0), |writer| {
                                writer.write_der(signed_attrs_der);
                            });

                            // Signature algorithm
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&rsa_encryption_oid);
                                writer.next().write_null();
                            });

                            // Signature
                            writer.next().write_bytes(signature);
                        });
                    });
                });
            });
        });
    });

    Ok(cms)
}