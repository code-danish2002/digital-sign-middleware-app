// src/pdf_signer.rs
use crate::{SignatureArea, sign_hash};
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use lopdf::{Document, Object, dictionary};
use num_bigint::BigUint;
use pkcs11::Ctx;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::Arc;
use x509_parser::prelude::*;
use yasna;
use hex;

pub async fn sign_and_embed_pdf(
    pkcs11_ctx: Arc<Ctx>,
    pdf_bytes: &[u8],
    slot_id: u64,
    cka_id: &str,
    sig_area: &SignatureArea,
) -> Result<Vec<u8>> {
    println!("--- Starting PDF Signing and Embedding ---");

    // First pass: Prepare document with placeholder
    let mut doc = Document::load_from(Cursor::new(pdf_bytes))
        .context("Failed to parse PDF document")?;

    let sig_dict_id = doc.new_object_id();
    let sig_field_id = doc.new_object_id();

    // Reserve space for CMS (use a more generous size)
    let placeholder_size = 30000; // Increased size
    let placeholder = "A".repeat(placeholder_size);

    // Create signature dictionary with placeholder
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

    // Create appearance stream content
    let mut content_operations = Vec::new();

    // Begin text
    content_operations.push(lopdf::content::Operation {
        operator: "BT".into(),
        operands: vec![],
    });

    // Set font and size
    content_operations.push(lopdf::content::Operation {
        operator: "Tf".into(),
        operands: vec![
            Object::Name("Helv".into()),
            Object::Integer(10),
        ],
    });

    // Position cursor
    content_operations.push(lopdf::content::Operation {
        operator: "Td".into(),
        operands: vec![
            Object::Integer(2),
            Object::Integer(2),
        ],
    });

    // Add signature text
    let date_line = format!("Date: {}", Utc::now().format("%Y.%m.%d %H:%M:%S"));
    let lines = vec![
        "Digitally signed by".to_string(),
        formatted_subject,
        date_line,
    ];

    for line in lines {
        content_operations.push(lopdf::content::Operation {
            operator: "Tj".into(),
            operands: vec![Object::string_literal(line)],
        });
        content_operations.push(lopdf::content::Operation {
            operator: "T*".into(),
            operands: vec![],
        });
    }

    // End text
    content_operations.push(lopdf::content::Operation {
        operator: "ET".into(),
        operands: vec![],
    });

    // Create content object
    let content = lopdf::content::Content {
        operations: content_operations,
    };

    // Create appearance resources
    let font_id = doc.new_object_id();
    doc.objects.insert(
        font_id,
        Object::Dictionary(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica"
        }),
    );

    // Create appearance stream
    let appearance_id = doc.new_object_id();
    let bbox = vec![
        Object::Integer(0),
        Object::Integer(0),
        Object::Integer(sig_area.width as i64),
        Object::Integer(sig_area.height as i64),
    ];
    
    let ap_dict = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Form",
        "BBox" => Object::Array(bbox),
        "Resources" => dictionary! {
            "Font" => dictionary! {
                "Helv" => Object::Reference(font_id)
            }
        }
    };

    let stream_dict = lopdf::Dictionary::from(ap_dict);
    let stream = lopdf::Stream::new(stream_dict, content.encode()?);
    doc.objects.insert(appearance_id, Object::Stream(stream));

    // Handle page coordinates
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

    // Convert coordinates (assuming y=0 is at top in input)
    let pdf_y_bottom = page_height - (sig_area.y + sig_area.height);
    let pdf_y_top = page_height - sig_area.y;

    // Create signature field dictionary
    let sig_field_dict = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "Rect" => Object::Array(vec![
            Object::Real(sig_area.x as f32),
            Object::Real(pdf_y_bottom as f32),
            Object::Real((sig_area.x + sig_area.width) as f32),
            Object::Real(pdf_y_top as f32)
        ]),
        "F" => 132,
        "FT" => "Sig",
        "V" => Object::Reference(sig_dict_id),
        "T" => Object::string_literal("Signature1"),
        "AP" => dictionary! { "N" => Object::Reference(appearance_id) }
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

    // ===== CRITICAL: Update document catalog for AcroForm =====
    // Get the root/catalog object ID first
    let catalog_id = doc.trailer.get(b"Root")
        .map_err(|_| anyhow!("Root not found in trailer"))?
        .as_reference()
        .map_err(|_| anyhow!("Root is not a reference"))?;

    // Check if AcroForm exists
    let needs_acro_form = {
        let catalog_dict = doc.objects.get(&catalog_id)
            .ok_or_else(|| anyhow!("Catalog object not found"))?
            .as_dict()
            .map_err(|_| anyhow!("Catalog object is not a dictionary"))?;
        
        !catalog_dict.has(b"AcroForm")
    };

    if needs_acro_form {
        // Create new AcroForm
        let acro_form_id = doc.new_object_id();
        let acro_form_dict = dictionary! {
            "Fields" => Object::Array(vec![Object::Reference(sig_field_id)]),
            "SigFlags" => 3
        };
        doc.objects.insert(acro_form_id, Object::Dictionary(acro_form_dict));
        
        // Update catalog
        let catalog_dict = doc.objects.get_mut(&catalog_id)
            .ok_or_else(|| anyhow!("Catalog object not found"))?
            .as_dict_mut()
            .map_err(|_| anyhow!("Catalog object is not a dictionary"))?;
        catalog_dict.set(b"AcroForm", Object::Reference(acro_form_id));
    } else {
        // Update existing AcroForm
        let acro_form_ref = {
            let catalog_dict = doc.objects.get(&catalog_id)
                .ok_or_else(|| anyhow!("Catalog object not found"))?
                .as_dict()
                .map_err(|_| anyhow!("Catalog object is not a dictionary"))?;
            
            catalog_dict.get(b"AcroForm")
                .map_err(|_| anyhow!("AcroForm reference not found"))?
                .as_reference()
                .map_err(|_| anyhow!("AcroForm is not a reference"))?
        };

        let acro_form_dict = doc.objects.get_mut(&acro_form_ref)
            .ok_or_else(|| anyhow!("AcroForm object not found"))?
            .as_dict_mut()
            .map_err(|_| anyhow!("AcroForm object is not a dictionary"))?;

        if acro_form_dict.has(b"Fields") {
            let fields = acro_form_dict.get_mut(b"Fields")
                .map_err(|_| anyhow!("Fields not found in AcroForm"))?
                .as_array_mut()
                .map_err(|_| anyhow!("Fields is not an array"))?;
            fields.push(Object::Reference(sig_field_id));
        } else {
            acro_form_dict.set(b"Fields", Object::Array(vec![Object::Reference(sig_field_id)]));
        }
        acro_form_dict.set(b"SigFlags", 3);
    }

    // Save to find exact placeholder position
    let mut temp_buffer = Cursor::new(Vec::new());
    doc.save_to(&mut temp_buffer)?;
    let temp_bytes = temp_buffer.into_inner();

    // Find placeholder position
    let placeholder_start = temp_bytes
        .windows(placeholder.len())
        .position(|window| window == placeholder.as_bytes())
        .context("Could not find signature placeholder")?;

    let placeholder_end = placeholder_start + placeholder.len();

    // Calculate ByteRange (CORRECTED)
    let byte_range = vec![
        0,
        placeholder_start as i64,
        placeholder_end as i64,
        (temp_bytes.len() - placeholder_end) as i64,
    ];

    // Update ByteRange in signature dictionary
    let sig_dict_mut = doc
        .objects
        .get_mut(&sig_dict_id)
        .ok_or_else(|| anyhow!("Signature dictionary not found"))?
        .as_dict_mut()
        .map_err(|_| anyhow!("Signature object is not a dictionary"))?;

    sig_dict_mut.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(byte_range[0]),
            Object::Integer(byte_range[1]),
            Object::Integer(byte_range[2]),
            Object::Integer(byte_range[3]),
        ]),
    );

    // Second pass: Calculate document hash
    let mut hasher = Sha256::new();
    hasher.update(&temp_bytes[0..byte_range[1] as usize]);
    hasher.update(&temp_bytes[byte_range[2] as usize..byte_range[2] as usize + byte_range[3] as usize]);
    let doc_hash = hasher.finalize().to_vec();

    // Create signed attributes
    let signed_attrs = create_signed_attributes(&doc_hash)
        .context("Failed to create signed attributes")?;

    // Hash the signed attributes
    let mut attrs_hasher = Sha256::new();
    attrs_hasher.update(&signed_attrs);
    let attrs_hash = attrs_hasher.finalize().to_vec();

    // Get signature from token
    let (signature, certificate_der) = sign_hash(pkcs11_ctx, slot_id, cka_id, &attrs_hash)
        .await
        .context("Failed to get signature from token")?;

    // Create CMS with signed attributes
    let pkcs7_container = create_cms(&signature, &certificate_der, &signed_attrs)
        .context("Failed to create CMS container")?;

    // Third pass: Embed final signature
    let mut final_buffer = Cursor::new(Vec::new());
    doc.save_to(&mut final_buffer)?;
    let mut final_bytes = final_buffer.into_inner();

    // Replace placeholder with hex-encoded signature (CORRECTED PADDING)
    let pkcs7_hex = hex::encode(&pkcs7_container).to_uppercase();
    if pkcs7_hex.len() > (placeholder_size - 2) {
        return Err(anyhow!(
            "Signature too large ({} chars), max allowed: {} chars",
            pkcs7_hex.len(),
            placeholder_size - 2
        ));
    }

    // Proper padding with < and >
    let padding_needed = placeholder_size - 2 - pkcs7_hex.len();
    let pkcs7_padded = format!("<{}{}>", pkcs7_hex, " ".repeat(padding_needed));
    final_bytes[placeholder_start..placeholder_end].copy_from_slice(pkcs7_padded.as_bytes());

    println!("--- PDF Signing and Embedding Finished ---");
    Ok(final_bytes)
}
fn format_subject(subject: &str) -> String {
    // Extract common name (CN) if available
    if let Some(cn_start) = subject.find("CN=") {
        let cn = &subject[cn_start + 3..];
        if let Some(end) = cn.find(',') {
            cn[..end].to_string()
        } else {
            cn.to_string()
        }
    } else {
        // Fallback to full subject
        subject
            .replace(" /", "\n/")
            .trim_start_matches('/')
            .to_string()
    }
}

fn create_signed_attributes(doc_hash: &[u8]) -> Result<Vec<u8>> {
    // content-type: id-data (1.2.840.113549.1.7.1)
    let content_type_oid =
        yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 1]);

    // message-digest: SHA256 hash of document
    let message_digest_oid =
        yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 4]);

    let signed_attrs = yasna::construct_der(|writer| {
        writer.write_set(|writer| {
            // Attribute 1: content-type
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&content_type_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_oid(&content_type_oid);
                });
            });

            // Attribute 2: message-digest
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&message_digest_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_bytes(doc_hash);
                });
            });
        })
    });

    Ok(signed_attrs)
}

fn create_cms(signature: &[u8], certificate: &[u8], signed_attrs_der: &[u8]) -> Result<Vec<u8>> {
    // Parse certificate for issuer/serial
    let (_, cert) = X509Certificate::from_der(certificate)
        .map_err(|e| anyhow!("Certificate parse error: {}", e))?;

    // Get the DER-encoded bytes of the issuer's name
    let issuer_der = cert.tbs_certificate.issuer.as_raw();

    // Get serial number as BigUint
    let serial = &cert.tbs_certificate.serial;
    let serial_der = encode_der_integer(serial);

    let mut sid = Vec::new();
    sid.push(0x30); // SEQUENCE
    let len = issuer_der.len() + serial_der.len();
    if len < 128 {
        sid.push(len as u8);
    } else if len < 256 {
        sid.push(0x81);
        sid.push(len as u8);
    } else {
        return Err(anyhow!("IssuerAndSerialNumber too large"));
    }
    sid.extend_from_slice(issuer_der);
    sid.extend_from_slice(&serial_der);

    // OIDs
    let signed_data_oid =
        yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 2]);
    let data_oid = yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 1]);
    let sha256_oid = yasna::models::ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]);
    let sha256_rsa_oid =
        yasna::models::ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11]);

    let cms_data = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // contentType
            writer.next().write_oid(&signed_data_oid);

            // content [0]
            writer
                .next()
                .write_tagged_implicit(yasna::Tag::context(0), |writer| {
                    writer.write_sequence(|writer| {
                        // version
                        writer.next().write_u8(1);

                        // digestAlgorithms
                        writer.next().write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&sha256_oid);
                                writer.next().write_null();
                            });
                        });

                        // encapContentInfo
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&data_oid);
                            // No content for detached signature
                        });

                        // certificates [0]
                        writer
                            .next()
                            .write_tagged_implicit(yasna::Tag::context(0), |writer| {
                                writer.write_sequence(|writer| {
                                    writer.next().write_sequence(|writer| {
                                        writer.next().write_der(certificate);
                                    });
                                });
                            });

                        // signerInfos
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                // version
                                writer.next().write_u8(1);

                                // sid [0]
                                writer.next().write_tagged_implicit(
                                    yasna::Tag::context(0),
                                    |writer| {
                                        writer.write_bytes(&sid);
                                    },
                                );

                                // digestAlgorithm
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_oid(&sha256_oid);
                                    writer.next().write_null();
                                });

                                // signedAttrs [0]
                                writer.next().write_tagged_implicit(
                                    yasna::Tag::context(0),
                                    |writer| {
                                        writer.write_bytes(signed_attrs_der);
                                    },
                                );

                                // signatureAlgorithm
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_oid(&sha256_rsa_oid);
                                    writer.next().write_null();
                                });

                                // signature
                                writer.next().write_bytes(signature);
                            });
                        });
                    });
                });
        });
    });

    Ok(cms_data)
}

fn encode_der_integer(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.is_empty() || (bytes[0] & 0x80) != 0 {
        let mut result = vec![0];
        result.extend_from_slice(&bytes);
        result
    } else {
        bytes
    }
}
