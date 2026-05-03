import streamlit as st


def update_vault_box(passwordManager):
    if "update_success" not in st.session_state:
        st.session_state.update_success = False
    if "form_key" not in st.session_state:
        st.session_state.form_key = 0

    update_site = st.text_input(
        "Site",
        placeholder="e.g. www.example.com",
        key=f"update_site_{st.session_state.form_key}",
    )

    update_username = st.text_input(
        "username",
        placeholder="e.g. zumaBeeh",
        key=f"update_username_{st.session_state.form_key}",
    )

    update_site_password = st.text_input(
        "Site Password",
        placeholder="e.g. password123",
        type="password",
        key=f"update_password_{st.session_state.form_key}",
    )

    if st.button("Update Vault →"):
        try:
            if (
                update_site.strip()
                and update_username.strip()
                and update_site_password.strip()
            ):
                passwordManager.update_credential(
                    st.session_state.name,
                    st.session_state.password,
                    update_site.strip(),
                    update_username.strip(),
                    update_site_password.strip(),
                )
                st.session_state.update_success = True
                st.session_state.form_key += 1
                st.success("Password Added Sucessfully")
                st.rerun()
        except Exception as e:
             st.error(f"Error Happened During Updating Vault: {e}")

    if st.session_state.update_success:
        st.success("✅ Password Added Successfully")
        st.session_state.update_success = False
