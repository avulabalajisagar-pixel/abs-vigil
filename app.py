import streamlit as st
import numpy as np
import requests
import re
import base64
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import urlparse


# ---------------------------------
# ABS VIGIL Configuration
# ---------------------------------

st.set_page_config(
    page_title="ABS VIGIL | Advanced Behavioral Shield",
    page_icon="🛡️",
    layout="centered"
)


st.title("🛡️ ABS VIGIL")

st.subheader(
    "Advanced Behavioral Shield"
)

st.write(
    """
    An intelligent cybersecurity platform to analyze QR codes,
    URLs, and suspicious links for phishing threats,
    malicious indicators, and threat intelligence insights.
    """
)


# ---------------------------------
# URL Validation
# ---------------------------------

def valid_url(url):

    try:

        result = urlparse(url)

        return all([
            result.scheme in ["http", "https"],
            result.netloc
        ])

    except Exception:

        return False



# ---------------------------------
# Local Threat Analysis Engine
# ---------------------------------

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
        "payment",
        "wallet",
        "crypto"

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
            "Direct IP address detected instead of domain"
        )



    if "@" in url:

        risk_score += 25

        reasons.append(
            "Possible URL spoofing using @ symbol"
        )



    if url.count("-") > 3:

        risk_score += 10

        reasons.append(
            "Multiple hyphens detected"
        )



    if risk_score > 100:

        risk_score = 100



    if risk_score >= 70:

        risk_level = "High Risk 🔴"


    elif risk_score >= 40:

        risk_level = "Medium Risk 🟡"


    else:

        risk_level = "Low Risk 🟢"



    if not reasons:

        reasons.append(
            "No suspicious indicators detected"
        )



    return {

        "Threat Level": risk_level,

        "Risk Score": f"{risk_score}/100",

        "Analysis": reasons

    }



# ---------------------------------
# VirusTotal Threat Intelligence
# ---------------------------------

def check_virustotal(url):


    try:

        api_key = st.secrets["VT_API_KEY"]


    except Exception:

        return "VirusTotal API key not configured"



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

        return "Network error while connecting to VirusTotal"



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

            f"VirusTotal request failed "
            f"Status Code: {response.status_code}"

        )



# ---------------------------------
# QR Code Security Scanner
# ---------------------------------

st.divider()

st.subheader(
    "📱 QR Code Threat Scanner"
)



uploaded_file = st.file_uploader(

    "Upload QR Code Image",

    type=[
        "png",
        "jpg",
        "jpeg"
    ]

)



if uploaded_file:


    image = Image.open(
        uploaded_file
    )


    img_array = np.array(
        image.convert("L")
    )


    result = decode(
        img_array
    )



    if result:


        qr_data = result[0].data.decode(
            "utf-8"
        )



        st.success(
            "QR Code successfully decoded"
        )


        st.write(
            "Extracted Data:"
        )


        st.code(
            qr_data
        )



        if valid_url(qr_data):


            qr_result = analyze_url(
                qr_data
            )


            st.subheader(
                "🛡️ ABS VIGIL Analysis"
            )


            st.json(
                qr_result
            )



            if st.button(
                "🔍 Scan QR URL with VirusTotal"
            ):


                vt = check_virustotal(
                    qr_data
                )


                st.subheader(
                    "VirusTotal Intelligence"
                )


                st.write(
                    vt
                )



        else:


            st.warning(
                "QR code does not contain a valid URL"
            )



    else:


        st.warning(
            "No QR code detected"
        )



# ---------------------------------
# Manual URL Scanner
# ---------------------------------

st.divider()


st.subheader(
    "🌐 Website Threat Scanner"
)



url = st.text_input(
    "Enter website URL"
)



if st.button(
    "Analyze Threat"
):


    if not url:


        st.error(
            "Please enter a URL"
        )



    elif not valid_url(url):


        st.error(
            "Invalid URL format"
        )



    else:


        st.session_state["url"] = url



if "url" in st.session_state:


    scanned_url = st.session_state["url"]



    analysis = analyze_url(
        scanned_url
    )



    st.subheader(
        "🛡️ Behavioral Threat Analysis"
    )


    st.json(
        analysis
    )



    if st.button(
        "🔍 Run VirusTotal Intelligence Scan"
    ):


        vt_result = check_virustotal(
            scanned_url
        )


        st.subheader(
            "VirusTotal Results"
        )


        st.write(
            vt_result
        )



# ---------------------------------
# Footer
# ---------------------------------

st.divider()


st.caption(
    "🛡️ ABS VIGIL | Advanced Behavioral Shield | Cyber Threat Intelligence Platform"
)
