use leptos::prelude::*;

/// Displays all system checkpoints and allows rollback operations.
///
/// Shows a table of all saved checkpoints with their ID, name, timestamp,
/// and username. Provides rollback and delete actions for each checkpoint.
#[component]
pub fn CheckpointList() -> impl IntoView {
    // Mock checkpoint data for UI demonstration
    // TODO: Replace with actual checkpoint data from AppState/backend
    #[derive(Clone, Debug)]
    struct CheckpointData {
        checkpoint_id: String,
        checkpoint_name: String,
        checkpoint_timestamp: u64,
        checkpoint_username: String,
    }

    let mock_checkpoints = vec![
        CheckpointData {
            checkpoint_id: "cp_2024_001".to_string(),
            checkpoint_name: "Before kernel hardening".to_string(),
            checkpoint_timestamp: 170000000,
            checkpoint_username: "admin".to_string(),
        },
    ];

    let checkpoints = RwSignal::new(mock_checkpoints);

    // Handle rollback action
    let handle_rollback = move |checkpoint_id: String| {
        // TODO: Trigger actual rollback via backend
        leptos::logging::log!("Rollback to checkpoint: {}", checkpoint_id);
    };

    // Handle delete action
    let handle_delete = move |checkpoint_id: String| {
        // TODO: Delete checkpoint via backend
        leptos::logging::log!("Delete checkpoint: {}", checkpoint_id);
        // Remove from local state for demonstration
        checkpoints.update(|cps| {
            cps.retain(|cp| cp.checkpoint_id != checkpoint_id)
        });
    };

    view! {
        <article class="checkpoint-list">
            <h1>"Checkpoints"</h1>

            <Show
                when=move || !checkpoints.get().is_empty()
                fallback=|| view! {
                    <section class="no-checkpoints">
                        <p>"No checkpoints available."</p>
                        <p>"Checkpoints are created automatically before applying hardening changes."</p>
                    </section>
                }
            >
                <section class="checkpoints-table">
                    <table>
                        <thead>
                            <tr>
                                <th>"Checkpoint ID"</th>
                                <th>"Name"</th>
                                <th>"Created"</th>
                                <th>"User"</th>
                                <th>"Actions"</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || checkpoints.get().iter().map(|checkpoint| {
                                let id_for_rollback = checkpoint.checkpoint_id.clone();
                                let id_for_delete = checkpoint.checkpoint_id.clone();

                                view! {
                                    <tr>
                                    <td><code>{checkpoint.checkpoint_id.clone()}</code></td>

                                    <td>{checkpoint.checkpoint_name.clone()}</td>

                                    <td>{checkpoint.checkpoint_timestamp}</td>

                                    <td>{checkpoint.checkpoint_username.clone()}</td>
                                        <td class="actions">
                                            <button
                                                on:click=move |_| handle_rollback(id_for_rollback.clone())
                                                class="rollback-button"
                                            >
                                                "Rollback"
                                            </button>
                                            <button
                                                on:click=move |_| handle_delete(id_for_delete.clone())
                                                class="delete-button"
                                            >
                                                "Delete"
                                            </button>
                                        </td>
                                    </tr>
                                }
                            }).collect::<Vec<_>>()}
                        </tbody>
                    </table>
                </section>
            </Show>
        </article>
    }
}
