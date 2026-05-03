import streamlit as st


def add_vault_box(passwordManager):
    if "add_success" not in st.session_state:
        st.session_state.add_success = False
    if "form_key" not in st.session_state:
        st.session_state.form_key = 0

    site = st.text_input(
        "Site",
        placeholder="e.g. www.example.com",
        key=f"site_{st.session_state.form_key}",
    )

    username = st.text_input(
        "username",
        placeholder="e.g. zumaBeeh",
        key=f"username_{st.session_state.form_key}",
    )

    site_password = st.text_input(
        "Site Password",
        placeholder="e.g. password123",
        type="password",
        key=f"password_{st.session_state.form_key}",
    )

    st.markdown(
        """
    <style>
    div[data-testid="stButton"] button {
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 8px;
    }
    div[data-testid="stButton"] button:hover {
        background-color: #45a049;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )
    if st.button("Add To Vault →", key="add_vault_btn"):
        try:
            if site.strip() and username.strip() and site_password.strip():
                passwordManager.add_credential(
                    st.session_state.name,
                    st.session_state.password,
                    site.strip(),
                    username.strip(),
                    site_password.strip(),
                )
                st.session_state.add_success = True
                st.session_state.form_key += 1
                st.success("Password Added Sucessfully")
                st.rerun()
        except Exception as e:
            st.error(f"Error Happened During Adding to Vault: {e}")

    if st.session_state.add_success:
        st.success("✅ Password Added Successfully")
        st.session_state.add_success = False
