import streamlit as st
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from CLI.app import PasswordManagerApp
from component.add_vault import add_vault_box
from component.update_vault import update_vault_box
from component.delete_vault import delete_vault_box
from component.export_import import import_vault, export_vault

st.set_page_config(layout="wide")
st.markdown(
    """
<style>
.stApp {
    background-color: #1e1e2e;
}
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<style>
.stApp {
    background-color: #1e1e2e;
}
h1, h2, h3 {
    color: white;
}
</style>
""",
    unsafe_allow_html=True,
)


st.title("Password Manager")


if "name" not in st.session_state:
    st.session_state.name = ""
if "submitted" not in st.session_state:
    st.session_state.submitted = False
if "password" not in st.session_state:
    st.session_state.password = ""


passwordManager = PasswordManagerApp()


if not st.session_state.submitted:
    st.markdown("## 👋 Welcome!")
    st.markdown("Please enter your name and master password to continue.")

    entered_name = st.text_input(
        "Your name",
        placeholder="e.g. Alice",
    )

    entered_master_password = st.text_input(
        "Master Password",
        placeholder="e.g. password123",
        type="password",
    )

    if st.button("Continue →"):
        if entered_name.strip() and entered_master_password.strip():
            st.session_state.name = entered_name.strip()
            st.session_state.password = entered_master_password.strip()
            st.session_state.submitted = True
            passwordManager.initialize_user(
                entered_name.strip(), entered_master_password.strip()
            )
            st.rerun()
        else:
            st.warning("Please fill in both fields before continuing.")

else:
    name = st.session_state.name

    st.markdown(f"## Hello, {name}! 🎉")

    if st.button("Read Vault →"):
        result = passwordManager.list_credentials(
            st.session_state.name, st.session_state.password
        )
        with st.container(border=True):
            st.subheader("Vault Unlocked")
            st.dataframe(
                [
                    {
                        "Site": r["site"],
                        "Username": r["username"],
                        "Password": r["password"],
                    }
                    for r in result
                ]
            )

    with st.container(border=True):
        st.subheader("Add New Entry")
        add_vault_box(passwordManager)

    with st.container(border=True):
        st.subheader("Update Entry")
        update_vault_box(passwordManager)

    with st.container(border=True):
        st.subheader("Delete Entry")
        delete_vault_box(passwordManager)

    col1, col2 = st.columns(2)

    with col1:
        export_vault(passwordManager)

    with col2:
        import_vault(passwordManager)
