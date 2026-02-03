# Application state shared across modules (minimal; avoid storing secrets here).


class AppState:
    current_user_id = None
