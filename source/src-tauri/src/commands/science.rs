use crate::science::{self, ScienceStartResult, ScienceStatus};
use crate::store::AppState;

#[tauri::command]
pub async fn get_science_status(
    state: tauri::State<'_, AppState>,
) -> Result<ScienceStatus, String> {
    Ok(science::status(&state).await)
}

#[tauri::command]
pub async fn start_science(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ScienceStartResult, String> {
    science::start(&app, &state).await
}

#[tauri::command]
pub async fn stop_science() -> Result<(), String> {
    science::stop().await
}

#[tauri::command]
pub async fn open_science(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    science::open(&app, &state).await
}
