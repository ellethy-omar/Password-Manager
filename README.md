# Password Manager

A secure credential management application with both a command-line interface and a Streamlit web UI.

---

## Requirements

**Python 3.8+** is required.

Install all dependencies with:

```bash
pip install -r requirements.txt
```

| Package        | Version | Purpose                                          |
| -------------- | ------- | ------------------------------------------------ |
| `pycryptodome` | 3.23.0  | Cryptographic operations (encryption/decryption) |
| `streamlit`    | 1.57.0  | Web-based user interface                         |

---

## Running the Application

### Streamlit UI

Launch the web interface with:

```bash
streamlit run ui/app.py
```

Then open your browser and navigate to `http://localhost:8501`.

---

## 🛠️ Makefile Workflows

A `Makefile` is provided for quickly running common workflows during development and testing. Default values for users, passwords, and sites are pre-configured at the top of the `Makefile` and can be overridden at runtime.

### Available Targets

| Target                   | Description                                                 |
| ------------------------ | ----------------------------------------------------------- |
| `make create-user`       | Initialize the primary test user vault                      |
| `make create-receiver`   | Initialize a secondary receiver user vault                  |
| `make add-credential`    | Add a first test credential                                 |
| `make add-credential-2`  | Add a second test credential                                |
| `make retrieve`          | Retrieve a credential by site                               |
| `make retrieve-failure`  | Attempt retrieval of a non-existent site (expected to fail) |
| `make update`            | Update the password for an existing credential              |
| `make delete-credential` | Delete a credential                                         |
| `make list`              | List all credentials for the primary user                   |
| `make list-receiver`     | List all credentials for the receiver user                  |
| `make verify`            | Verify the vault signature of the primary user              |
| `make verify-receiver`   | Verify the vault signature of the receiver user             |
| `make export-vault`      | Export the primary user's vault to the receiver             |
| `make import-vault`      | Import the exported vault into the receiver's account       |
| `make clean-data`        | Wipe all data in the `data/` directory                      |
| `make test-crud`         | Run the full CRUD test suite (Modules 1–3)                  |
| `make test-all`          | Run all tests end-to-end                                    |

### Running a Full Test Suite

```bash
make test-crud
```

### Overriding Default Values

You can override any variable inline:

```bash
make create-user USER=alice MASTER=my_secret_password
make add-credential SITE=google.com USERNAME=alice PASSWORD=p@ssw0rd
```

### Cleaning Up Test Data

```bash
make clean-data
```

> This permanently deletes all files inside the `data/` directory. Use with caution.

---
