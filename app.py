import streamlit as st
import cv2
import numpy as np
import requests
import re
from PIL import Image
from pyzbar.pyzbar import decode
import urllib.parse


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
    "Analyze QR codes and URLs for possible phishing or malicious activity."
)


# -------------------------------
# URL Analysis Function
# -------------------------------

def analyze_url(url):

    result = {
        "Risk": "Low",
        "Reasons": []
    }

    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "password",
        "free"
    ]


    for word in suspicious_words:
        if word in url.lower():
            result["Risk"] = "Medium"
            result["Reasons"].append(
                f"Suspicious keyword detected: {word}"
            )


    if len(url) > 100:
        result["Risk"] = "Medium"
        result["Reasons"].append(
            "Very long URL detected"
        )


    if re.search(
        r"\d+\.\d+\.\d+\.\d+",
        url
    ):
        result["Risk"] = "High"
        result["Reasons"].append(
            "URL contains IP address"
        )


    return result



# -------------------------------
# VirusTotal Function
# -------------------------------

def check_virustotal(url, api_key):

    if not api_key:
        return "API Key Missing"


    headers = {
        "x-apikey": api_key
    }


    url_id = (
        urllib.parse
        .quote(url, safe="")
    )


    endpoint = (
        f"https://www.virustotal.com/api/v3/urls/{url_id}"
    )


    response = requests.get(
        endpoint,
        headers=headers
    )


    if response.status_code == 200:
        data = response.json()

        stats = (
            data["data"]
            ["attributes"]
            ["last_analysis_stats"]
        )

        return stats

    else:
        return "Unable to check VirusTotal"



# -------------------------------
# QR Code Scanner
# -------------------------------


st.subheader("📷 Upload QR Code")

uploaded_file = st.file_uploader(
    "Upload QR image",
    type=[
        "png",
        "jpg",
        "jpeg"
    ]
)


if uploaded_file:


    image = Image.open(uploaded_file)

    img_array = np.array(image)


    decoded = decode(img_array)


    if decoded:

        qr_data = decoded[0].data.decode(
            "utf-8"
        )


        st.success(
            "QR Code Detected"
        )


        st.write(
            "Extracted URL:"
        )

        st.code(qr_data)


        analysis = analyze_url(qr_data)


        st.subheader(
            "Threat Analysis"
        )


        st.write(
            analysis
        )


    else:

        st.warning(
            "No QR code detected"
        )



# -------------------------------
# Manual URL Checker
# -------------------------------


st.subheader("🌐 URL Scanner")


url = st.text_input(
    "Enter URL"
)


if st.button(
    "Analyze URL"
):

    if url:

        result = analyze_url(url)

        st.json(result)


        api_key = st.text_input(
            "VirusTotal API Key",
            type="password"
        )


        if api_key:

            vt_result = check_virustotal(
                url,
                api_key
            )

            st.write(
                "VirusTotal Result:"
            )

            st.write(
                vt_result
            )

    else:

        st.error(
            "Enter a URL first"
        )
