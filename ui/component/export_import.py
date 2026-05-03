import streamlit as st


def export_vault(passwordManager):
    if "export_success" not in st.session_state:
        st.session_state.export_success = False
    if "form_key" not in st.session_state:
        st.session_state.form_key = 0

    with st.container(border=True):
        st.subheader("Export Your Vault To Another User")
        receiver = st.text_input(
            "Vault Receiver",
            placeholder="e.g. Alice",
            key=f"receiver_{st.session_state.form_key}",
        )

        if st.button("Send Vault"):
            try:
                if receiver.strip():
                    result = passwordManager.export_vault(
                        st.session_state.name,
                        st.session_state.password,
                        receiver.strip(),
                    )
                    st.success(f"Channel message: {result}")
                    st.session_state.export_success = True
                    st.session_state.form_key += 1
                    st.rerun()
            except Exception as e:
                st.error(f"Error Happened During Exporting Vault: {e}")

        if st.session_state.export_success:
            st.success("✅ Vault Exported Successfully")
            st.session_state.export_success = False


def import_vault(passwordManager):
    if "import_success" not in st.session_state:
        st.session_state.import_success = False
    if "form_key" not in st.session_state:
        st.session_state.form_key = 0

    with st.container(border=True):
        st.subheader("Import Another User's Vault")
        sender = st.text_input(
            "Vault Sender",
            placeholder="e.g. Bob",
            key=f"sender_{st.session_state.form_key}",
        )
        if st.button("Receive Vault"):
            try:
                if sender.strip():
                    result = passwordManager.import_vault(
                        st.session_state.name,
                        sender.strip(),
                        st.session_state.password,
                    )
                    st.success(f"Channel message: {result}")
                    st.session_state.import_success = True
                    st.session_state.form_key += 1
                    st.rerun()
            except Exception as e:
                st.error(f"Error Happened During Importing Vault: {e}")

        if st.session_state.import_success:
            st.success("✅ Vault Imported Successfully")
            st.session_state.import_success = False
