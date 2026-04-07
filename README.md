# Neverlose v3.3 Full SRC

## 🛠 Setup Tutorial

### 1\. Backend Server Configuration

The backend requires a PostgreSQL environment to handle data.

  * **Database:** Ensure **PostgreSQL** is installed and running (or use a compatible AI-regenerated server instance).
  * **Run the Server:**
    ```bash
    cd server/rust-server
    cargo run
    ```
  * **Seed Data:** Initialize the database by sending a POST request:
    ```bash
    curl -X POST http://localhost:30031/admin/seed
    ```

### 2\. Client Injection

Follow these steps to load the module into the game process.

  * **Launch Options:** Add `-insecure` to your CS:GO launch parameters in Steam.
  * **Execution:**
    1.  Navigate to the `Release` directory.
    2.  Launch **CS:GO**.
    3.  Run `injector.exe` to inject the module.
  * **Note:** If the game updates, slight modifications to the source code may be required to maintain compatibility.

-----

## 🔗 Neverlose

  * **v3.3:** https://neverlose.cc/
