import streamlit as st


def delete_vault_box(passwordManager):
    if "delete_success" not in st.session_state:
        st.session_state.delete_success = False
    if "form_key" not in st.session_state:
        st.session_state.form_key = 0

    delete_site = st.text_input(
        "Site",
        placeholder="e.g. www.example.com",
        key=f"delete_site_{st.session_state.form_key}",
    )

    delete_username = st.text_input(
        "username",
        placeholder="e.g. zumaBeeh",
        key=f"delete_username_{st.session_state.form_key}",
    )

    if st.button("Delete Vault →"):
        try:
            if delete_site.strip() and delete_username.strip():
                passwordManager.delete_credential(
                    st.session_state.name,
                    st.session_state.password,
                    delete_site.strip(),
                    delete_username.strip(),
                )
                st.session_state.delete_success = True
                st.session_state.form_key += 1
                st.success("Password Added Sucessfully")
                st.rerun()
        except Exception as e:
            st.error(f"Error Happened During Deleting Vault: {e}")

    if st.session_state.delete_success:
        st.success("✅ Password Deleted Successfully")
        st.session_state.delete_success = False
