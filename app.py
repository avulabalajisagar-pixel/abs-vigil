import streamlit as st
import numpy as np
import requests
import re
import base64
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import urlparse


# -------------------------------
# Page Configuration
# -------------------------------

st.set_page_config(
    page_title="Cyber Threat Analyzer",
    page_icon="🔐",
    layout="centered"
)


st.title("🔐 Cyber Threat Analyzer")

st.write(
    """
    Analyze QR codes and URLs for possible phishing,
    malicious indicators, and threat intelligence.
    """
)


# -------------------------------
# URL Validation
# -------------------------------

def valid_url(url):

    try:
        result = urlparse(url)

        return all([
            result.scheme in ["http", "https"],
            result.netloc
        ])

    except Exception:
        return False



# -------------------------------
# Local URL Threat Analysis
# -------------------------------

def analyze_url(url):

    risk_score = 0
    reasons = []


    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "password",
        "free",
        "gift",
        "confirm",
        "signin",
        "payment"
    ]


    for word in suspicious_words:

        if word in url.lower():

            risk_score += 10

            reasons.append(
                f"Suspicious keyword detected: {word}"
            )


    if len(url) > 100:

        risk_score += 15

        reasons.append(
            "Unusually long URL detected"
        )


    if re.search(
        r"\d+\.\d+\.\d+\.\d+",
        url
    ):

        risk_score += 30

        reasons.append(
            "URL contains direct IP address"
        )


    if "@" in url:

        risk_score += 25

        reasons.append(
            "URL contains @ symbol (possible spoofing)"
        )


    if url.count("-") > 3:

        risk_score += 10

        reasons.append(
            "Multiple hyphens detected"
        )


    if risk_score >= 50:

        risk_level = "High 🔴"

    elif risk_score >= 30:

        risk_level = "Medium 🟡"

    else:

        risk_level = "Low 🟢"



    if not reasons:

        reasons.append(
            "No suspicious indicators detected"
        )


    return {

        "Risk Level": risk_level,

        "Risk Score": f"{risk_score}/100",

        "Reasons": reasons

    }



# -------------------------------
# VirusTotal Integration
# -------------------------------

def check_virustotal(url):


    try:

        api_key = st.secrets["VT_API_KEY"]


    except Exception:

        return "VirusTotal API Key not configured"



    headers = {

        "x-apikey": api_key

    }



    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")



    endpoint = (

        f"https://www.virustotal.com/api/v3/urls/{url_id}"

    )



    try:

        response = requests.get(

            endpoint,

            headers=headers,

            timeout=10

        )


    except requests.exceptions.RequestException:

        return "Network error while contacting VirusTotal"



    if response.status_code == 200:


        data = response.json()


        stats = (

            data["data"]

            ["attributes"]

            ["last_analysis_stats"]

        )


        return stats



    elif response.status_code == 404:

        return "URL not found in VirusTotal database"



    else:

        return (

            f"VirusTotal scan failed "
            f"(Status: {response.status_code})"

        )



# -------------------------------
# QR Code Scanner
# -------------------------------

st.subheader("📷 QR Code Scanner")


uploaded_file = st.file_uploader(

    "Upload QR Code Image",

    type=[
        "png",
        "jpg",
        "jpeg"
    ]

)



if uploaded_file:


    image = Image.open(uploaded_file)


    img_array = np.array(
        image.convert("L")
    )


    result = decode(img_array)



    if result:


        qr_url = result[0].data.decode(
            "utf-8"
        )


        st.success(
            "QR Code Detected Successfully"
        )


        st.write(
            "Extracted Data:"
        )


        st.code(qr_url)



        if valid_url(qr_url):


            qr_analysis = analyze_url(qr_url)


            st.subheader(
                "🛡 QR Threat Analysis"
            )


            st.json(qr_analysis)



            if st.button(
                "Check QR URL with VirusTotal"
            ):


                vt_result = check_virustotal(
                    qr_url
                )


                st.subheader(
                    "🔍 VirusTotal Intelligence"
                )


                st.write(vt_result)



        else:


            st.warning(
                "QR does not contain a valid URL"
            )



    else:


        st.warning(
            "No QR code detected"
        )



# -------------------------------
# Manual URL Scanner
# -------------------------------

st.subheader("🌐 URL Scanner")


url = st.text_input(
    "Enter website URL"
)



if st.button(
    "Analyze Website"
):


    if not url:


        st.error(
            "Please enter a URL"
        )


    elif not valid_url(url):


        st.error(
            "Invalid URL format. Example: https://example.com"
        )


    else:


        st.session_state["analyzed_url"] = url



if "analyzed_url" in st.session_state:


    scanned_url = st.session_state["analyzed_url"]


    result = analyze_url(
        scanned_url
    )


    st.subheader(
        "🛡 Local Threat Analysis"
    )


    st.json(result)



    if st.button(
        "Run VirusTotal Scan"
    ):


        vt_result = check_virustotal(
            scanned_url
        )


        st.subheader(
            "🔍 VirusTotal Intelligence"
        )


        st.write(vt_result)



# -------------------------------
# Footer
# -------------------------------

st.divider()


st.caption(
    "Cyber Threat Analyzer | QR Phishing Detection + URL Intelligence"
)
