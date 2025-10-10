# --- Entry Point for Local Development ---
if __name__ == "__main__":
    import uvicorn
    from main import app
    # This allows running the app locally with `python run.py`
    uvicorn.run(app, host="127.0.0.1", port=9000, log_level="info", reload=True)