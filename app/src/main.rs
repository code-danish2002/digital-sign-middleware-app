// src/main.rs (project root)
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod pdf_signer;
mod pin_dialog;
mod server;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;

#[tokio::main]
async fn main() {
    println!("Main.rs Digital signing server starting...");
    // Run your WebSocket server in a background thread

    // Launch Tauri desktop application
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle().clone();
            tokio::spawn(async move {
                if let Err(e) = server::start(app_handle).await {
                    eprintln!("Digital signing server error: {}", e);
                }
            });
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            pin_dialog::submit_pin,
            pin_dialog::cancel_pin,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
