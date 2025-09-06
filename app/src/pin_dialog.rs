use tokio::sync::oneshot;
use std::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use urlencoding;
use std::sync::atomic::{AtomicU32, Ordering};
use tauri::Manager;
use tauri::Listener;
use tauri::Emitter;

static REQUEST_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

fn generate_request_id() -> u32 {
    REQUEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// Store pending PIN requests
lazy_static::lazy_static! {
    static ref PENDING_REQUESTS: Arc<Mutex<HashMap<u32, oneshot::Sender<String>>>> = 
        Arc::new(Mutex::new(HashMap::new()));
}

pub async fn show_pin_dialog(app_handle: &tauri::AppHandle, prompt: String) -> Result<String, String> {
    // Generate a unique request ID
    let request_id = generate_request_id();

    // Create a channel for the response
    let (sender, receiver) = oneshot::channel::<String>();
    
    // Store the sender for later use
    {
        let mut requests = PENDING_REQUESTS.lock().unwrap();
        requests.insert(request_id, sender);
    }
    
    // URL-encode the prompt
    let encoded_prompt = urlencoding::encode(&prompt);

    // Create a new window to display the PIN dialog
    let window_url = format!("/pin-dialog.html?request_id={}&prompt={}", request_id, encoded_prompt);
    
    let window = tauri::WebviewWindowBuilder::new(
        app_handle,
        format!("pin-dialog-{}", request_id),
        tauri::WebviewUrl::App(window_url.into())
    )
    .title("Smart Card PIN")
    .inner_size(360.0, 240.0)
    .resizable(false)
    .fullscreen(false)
    .decorations(true)
    .build()
    .map_err(|e| format!("Failed to create PIN dialog: {}", e))?;

    println!("Created PIN dialog window for request_id: {}", request_id);

    // Listen for events from the PIN dialog using global events
    let app_handle_clone = app_handle.clone();
    let listen_id = app_handle.listen("pin_submitted", move |event| {
        println!("Global pin_submitted event received: {}", event.payload());
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&event.payload()) {
            if let (Some(event_request_id), Some(pin)) = (
                payload.get("request_id").and_then(|v| v.as_u64()),
                payload.get("pin").and_then(|v| v.as_str())
            ) {
                println!("Processing PIN submission - event request_id: {}, our request_id: {}", event_request_id, request_id);
                if event_request_id as u32 == request_id {
                    println!("Request ID matches, processing PIN");
                    let sender = {
                        let mut requests = PENDING_REQUESTS.lock().unwrap();
                        requests.remove(&(event_request_id as u32))
                    };
                    if let Some(sender) = sender {
                        println!("Sending PIN through channel");
                        let _ = sender.send(pin.to_string());
                    } else {
                        println!("No pending request found for request_id: {}", event_request_id);
                    }
                }
            }
        }
    });

    // Listen for cancellation events
    let app_handle_clone2 = app_handle.clone();
    let listen_id_cancel = app_handle_clone2.listen("pin_cancelled", move |event| {
        println!("Global pin_cancelled event received: {}", event.payload());
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&event.payload()) {
            if let Some(event_request_id) = payload.get("request_id").and_then(|v| v.as_u64()) {
                if event_request_id as u32 == request_id {
                    println!("Cancellation request_id matches, processing cancellation");
                    let sender = {
                        let mut requests = PENDING_REQUESTS.lock().unwrap();
                        requests.remove(&(event_request_id as u32))
                    };
                    if let Some(sender) = sender {
                        let _ = sender.send(String::new());
                    }
                }
            }
        }
    });

    // Wait for the response
    let result = match tokio::time::timeout(std::time::Duration::from_secs(120), receiver).await {
        Ok(Ok(pin)) => {
            println!("Received PIN for request {}: {}", request_id, if pin.is_empty() { "CANCELLED" } else { "****" });
            Ok(pin)
        },
        Ok(Err(_)) => {
            println!("PIN request {} cancelled (channel error)", request_id);
            Err("PIN request cancelled".to_string())
        },
        Err(_) => {
            println!("PIN dialog {} timeout", request_id);
            Err("PIN dialog timeout (2 minutes)".to_string())
        }
    };

    // Stop listening and close the window
    app_handle.unlisten(listen_id);
    app_handle.unlisten(listen_id_cancel);
    let _ = window.close();
    
    result
}

#[tauri::command]
pub async fn submit_pin(request_id: u32, pin: String, app_handle: tauri::AppHandle) -> Result<(), String> {
    println!("Received PIN via submit_pin command: request_id={}, pin_length={}", request_id, pin.len());
    
    // Emit event instead of using global listener
    app_handle.emit("pin_submitted", serde_json::json!({
        "request_id": request_id,
        "pin": pin
    })).map_err(|e| format!("Failed to emit event: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub async fn cancel_pin(request_id: u32, app_handle: tauri::AppHandle) -> Result<(), String> {
    println!("Received cancel_pin command for request_id: {}", request_id);
    
    // Emit event instead of using global listener
    app_handle.emit("pin_cancelled", serde_json::json!({
        "request_id": request_id
    })).map_err(|e| format!("Failed to emit event: {}", e))?;
    
    Ok(())
}