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

    except:
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
        "signin"
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
            "Unusually long URL"
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

        risk="High"

    elif risk_score >=30:

        risk="Medium"

    else:

        risk="Low"



    return {

        "Risk Level": risk,

        "Risk Score": risk_score,

        "Reasons": reasons

    }



# -------------------------------
# VirusTotal Integration
# -------------------------------

def check_virustotal(url):


    try:

        api_key = st.secrets["VT_API_KEY"]


    except:

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



    response = requests.get(

        endpoint,

        headers=headers,

        timeout=10

    )



    if response.status_code == 200:


        data=response.json()


        stats=(

            data["data"]

            ["attributes"]

            ["last_analysis_stats"]

        )


        return stats



    elif response.status_code == 404:

        return "URL not found in VirusTotal database"


    else:

        return "VirusTotal scan failed"



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


    img_array=np.array(image)


    result=decode(img_array)



    if result:


        qr_url=result[0].data.decode(
            "utf-8"
        )


        st.success(
            "QR Code Detected"
        )


        st.write(
            "Extracted Data:"
        )


        st.code(qr_url)



        if valid_url(qr_url):


            analysis=analyze_url(qr_url)


            st.subheader(
                "🛡 Threat Analysis"
            )


            st.json(analysis)



            if st.button(
                "Check VirusTotal"
            ):


                vt=check_virustotal(
                    qr_url
                )


                st.subheader(
                    "VirusTotal Result"
                )


                st.write(vt)


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


url=st.text_input(
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
            "Invalid URL format"
        )


    else:


        result=analyze_url(url)


        st.subheader(
            "🛡 Local Threat Analysis"
        )


        st.json(result)



        if st.button(
            "Run VirusTotal Scan"
        ):


            vt_result=check_virustotal(
                url
            )


            st.subheader(
                "🔍 VirusTotal Intelligence"
            )


            st.write(
                vt_result
            )



# -------------------------------
# Footer
# -------------------------------


st.divider()


st.caption(
    "Cyber Threat Analyzer | QR Phishing Detection + URL Intelligence"
)
