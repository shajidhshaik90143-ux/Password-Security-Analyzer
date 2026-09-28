import streamlit as st
from src.analyzer import analyze_password
from src.generator import generate_password, generate_passphrase
from src.breach import check_hibp_k_anonymity
import pandas as pd

st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1250px;}
.hero {
    padding: 1.6rem 1.8rem;
    border-radius: 18px;
    background: linear-gradient(135deg, #111827, #1f2937);
    color: white;
    margin-bottom: 1.2rem;
}
.hero h1 {margin:0 0 .35rem 0;}
.metric-card {
    border: 1px solid rgba(128,128,128,.25);
    border-radius: 14px;
    padding: 1rem;
}
.small {color:#6b7280;font-size:.9rem;}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
<h1>🔐 Password Security Analyzer</h1>
<p>Analyze password strength, entropy, risky patterns, reuse signals, and resistance indicators — locally by default.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ Settings")
    check_breach = st.checkbox(
        "Enable Have I Been Pwned check",
        value=False,
        help="Uses the HIBP k-anonymity API. Only a SHA-1 prefix is sent; the password itself is never sent."
    )
    show_password = st.checkbox("Show password while typing", value=False)
    st.divider()
    st.subheader("What is analyzed?")
    st.markdown("""
- Length and character diversity
- Estimated entropy
- Common-password indicators
- Repetition and sequences
- Keyboard patterns
- Year/date-like patterns
- Dictionary-style words
- Overall score and recommendations
""")
    st.caption("Privacy: the local analyzer does not store your password.")

tab1, tab2, tab3 = st.tabs(["🔎 Analyze", "🎲 Generate", "ℹ️ About"])

with tab1:
    st.subheader("Analyze a password")
    ptype = "default" if show_password else "password"
    password = st.text_input("Enter password", type=ptype, placeholder="Type a password to analyze")

    if password:
        result = analyze_password(password)

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Security Score", f"{result['score']}/100")
        with c2:
            st.metric("Strength", result["label"])
        with c3:
            st.metric("Entropy", f"{result['entropy_bits']:.1f} bits")
        with c4:
            st.metric("Length", f"{len(password)} chars")

        st.progress(result["score"] / 100)

        if result["score"] >= 80:
            st.success("This password has a strong security profile based on the local checks.")
        elif result["score"] >= 60:
            st.warning("Moderate security profile. Follow the recommendations below.")
        else:
            st.error("Weak security profile. Replace this password with a longer, unique password.")

        left, right = st.columns(2)
        with left:
            st.subheader("📊 Composition")
            composition = result["composition"]
            df = pd.DataFrame({
                "Category": list(composition.keys()),
                "Present": ["Yes" if v else "No" for v in composition.values()]
            })
            st.dataframe(df, hide_index=True, use_container_width=True)

            st.subheader("🧠 Risk Signals")
            if result["risks"]:
                for risk in result["risks"]:
                    st.warning(risk)
            else:
                st.success("No major risky patterns detected.")

        with right:
            st.subheader("💡 Recommendations")
            for rec in result["recommendations"]:
                st.info(rec)

            st.subheader("🛡️ Resistance Indicators")
            resistance = result["resistance"]
            rdf = pd.DataFrame({
                "Attack model": list(resistance.keys()),
                "Estimated status": list(resistance.values())
            })
            st.dataframe(rdf, hide_index=True, use_container_width=True)

        if check_breach:
            with st.spinner("Checking breach corpus via k-anonymity…"):
                breach = check_hibp_k_anonymity(password)
            if breach["status"] == "ok":
                if breach["count"] > 0:
                    st.error(f"⚠️ This password appears in the HIBP corpus {breach['count']:,} times. Do not use it.")
                else:
                    st.success("No match was returned by HIBP for this password.")
            else:
                st.warning(f"Breach check unavailable: {breach['message']}")

        with st.expander("Technical details"):
            st.json({
                "score": result["score"],
                "label": result["label"],
                "entropy_bits": result["entropy_bits"],
                "character_pool": result["pool_size"],
                "composition": result["composition"],
                "risks": result["risks"],
            })

with tab2:
    st.subheader("Generate a strong password")
    c1, c2 = st.columns(2)
    with c1:
        length = st.slider("Password length", 12, 64, 20)
        use_upper = st.checkbox("Uppercase", True)
        use_lower = st.checkbox("Lowercase", True)
        use_digits = st.checkbox("Digits", True)
        use_symbols = st.checkbox("Symbols", True)
        avoid_ambiguous = st.checkbox("Avoid ambiguous characters", True)
    with c2:
        st.markdown("### Generated password")
        if st.button("🎲 Generate password", type="primary", use_container_width=True):
            try:
                generated = generate_password(
                    length, use_upper, use_lower, use_digits, use_symbols, avoid_ambiguous
                )
                st.code(generated, language=None)
                analysis = analyze_password(generated)
                st.success(f"Score: {analysis['score']}/100 • {analysis['label']} • {analysis['entropy_bits']:.1f} bits")
            except ValueError as e:
                st.error(str(e))

    st.divider()
    st.subheader("🧩 Passphrase generator")
    words = st.slider("Number of words", 4, 10, 5)
    separator = st.selectbox("Separator", ["-", " ", "_", ".", ""])
    if st.button("Generate passphrase"):
        phrase = generate_passphrase(words, separator)
        st.code(phrase, language=None)
        st.caption(f"Generated from a local word list. Approximate entropy: {words * 11:.0f}+ bits depending on the list.")

with tab3:
    st.subheader("About this project")
    st.markdown("""
**Password Security Analyzer** is a defensive cybersecurity project designed to demonstrate:

1. Password composition analysis
2. Entropy estimation
3. Pattern and sequence detection
4. Weak-password heuristics
5. Security scoring
6. Cryptographically secure password generation
7. Optional HIBP k-anonymity breach checking
8. A Streamlit dashboard suitable for a college/project demonstration

### Privacy model
The local analyzer operates entirely on the entered password in application memory. It does not write passwords to files or databases. The optional HIBP check uses a k-anonymity design: only the first five characters of the SHA-1 hash are sent to the service.

### Important
A high score does not guarantee that a password has never been exposed. Use a unique password for every account and prefer a password manager.
""")
