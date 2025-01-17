import os
import time
import re
import base64
import google.generativeai as genai
from flask import Flask, render_template_string, request, jsonify
from email import parser, policy
import dkim
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'AIzaSyDPoaPx17CL68O0xhNBqaubSvBB6f2GUXw'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# [Previous HTML_TEMPLATE remains the same]

def detect_ai_patterns(headers, header_text):
    """Enhanced detection of AI-generated headers"""
    ai_indicators = []
    confidence_factors = []
    
    # 1. Check Message-ID patterns
    message_id = headers.get('Message-ID', '')
    if message_id:
        # Check for overly structured or predictable patterns
        if re.search(r'[a-zA-Z]+-\d{8}-\d+@', message_id):
            ai_indicators.append("Suspiciously structured Message-ID format")
            confidence_factors.append(0.7)
            
        # Check for common AI-generated patterns
        if re.search(r'(promo|marketing|campaign)-\d{8}', message_id):
            ai_indicators.append("Marketing-template style Message-ID")
            confidence_factors.append(0.6)
    
    # 2. Analyze Received headers sequence
    received_headers = headers.get_all('Received', [])
    if received_headers:
        # Check timestamp patterns
        timestamps = []
        for header in received_headers:
            timestamp_match = re.search(r';(.*?)(?:\(.*?\))?\s*$', header)
            if timestamp_match:
                try:
                    timestamp_str = timestamp_match.group(1).strip()
                    timestamp = parsedate_to_datetime(timestamp_str)
                    timestamps.append(timestamp)
                except (ValueError, TypeError):
                    continue
        
        if timestamps:
            # Check for perfectly spaced timestamps
            time_diffs = [(timestamps[i] - timestamps[i+1]).total_seconds() 
                         for i in range(len(timestamps)-1)]
            
            if len(time_diffs) > 1:
                # Check if time differences are too uniform
                if len(set(int(diff) for diff in time_diffs)) == 1:
                    ai_indicators.append("Suspiciously uniform timing between servers")
                    confidence_factors.append(0.9)
                
                # Check for unrealistic timing
                if any(diff < 0.1 for diff in time_diffs):
                    ai_indicators.append("Unrealistically fast server processing")
                    confidence_factors.append(0.8)
    
    # 3. Check for template-like headers
    marketing_headers = ['X-Campaign-ID', 'X-Tracking-ID', 'List-Unsubscribe', 'Precedence']
    marketing_count = sum(1 for header in marketing_headers if header in headers)
    if marketing_count >= 3:
        ai_indicators.append("Common marketing template headers present")
        confidence_factors.append(0.5)
    
    # 4. Analyze Authentication Headers
    auth_results = headers.get('Authentication-Results', '')
    if 'dkim=pass' in auth_results and 'spf=pass' in auth_results:
        # Check if authentication looks too perfect
        if re.search(r'header\.i=@[\w-]+\.com', auth_results):
            ai_indicators.append("Suspiciously perfect authentication results")
            confidence_factors.append(0.4)
    
    # 5. Check for perfect formatting
    if all(h in headers for h in ['From', 'To', 'Subject', 'Date', 'Message-ID']):
        perfect_format = True
        for header in headers.items():
            if not re.match(r'^[A-Za-z-]+: .+$', str(header)):
                perfect_format = False
                break
        if perfect_format:
            ai_indicators.append("Unusually perfect header formatting")
            confidence_factors.append(0.6)
    
    # 6. Content consistency check
    domain_pattern = r'@([\w.-]+)'
    domains = re.findall(domain_pattern, header_text)
    if len(set(domains)) == 1:
        ai_indicators.append("Suspiciously consistent domain usage")
        confidence_factors.append(0.5)
    
    # 7. Check for future dates
    date_str = headers.get('Date', '')
    if date_str:
        try:
            email_date = parsedate_to_datetime(date_str)
            if email_date > datetime.now() + timedelta(days=1):
                ai_indicators.append("Email date is in the future")
                confidence_factors.append(0.9)
        except (ValueError, TypeError):
            pass
    
    # Calculate overall AI probability
    ai_probability = min(sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0, 1.0) * 100
    
    return {
        'indicators': ai_indicators,
        'probability': round(ai_probability, 2),
        'confidence_factors': confidence_factors
    }

def analyze_headers(header_text):
    try:
        # Parse the email headers
        parser_instance = parser.HeaderParser(policy=policy.default)
        headers = parser_instance.parsestr(header_text)
        
        # Enhanced AI pattern detection
        ai_analysis = detect_ai_patterns(headers, header_text)
        
        # Rest of the existing analysis functions...
        parsed_headers = parse_header_structure(headers)
        auth_analysis = analyze_authentication(headers)
        routing_analysis = analyze_routing(headers)
        
        # Enhanced analysis prompt
        analysis_prompt = f"""Analyze these email headers for potential spoofing and AI generation:

        Parsed Headers:
        {parsed_headers}

        Authentication Analysis:
        - DKIM Present: {auth_analysis['dkim_present']}
        - SPF Present: {auth_analysis['spf_present']}
        - Authentication Results: {auth_analysis['auth_results']}

        Routing Analysis:
        {routing_analysis}

        AI Pattern Analysis:
        - Indicators: {ai_analysis['indicators']}
        - AI Generation Probability: {ai_analysis['probability']}%
        - Confidence Factors: {ai_analysis['confidence_factors']}

        Please provide a comprehensive security analysis including:
        [Rest of the prompt remains the same...]
        """

        # Get Gemini AI analysis
        model = genai.GenerativeModel('gemini-pro')
        start_time = time.time()
        response = model.generate_content(analysis_prompt)
        analysis_time = round(time.time() - start_time, 2)

        # Enhanced result with AI analysis
        analysis_result = {
            'parsed_headers': parsed_headers,
            'auth_analysis': auth_analysis,
            'routing_analysis': routing_analysis,
            'ai_analysis': ai_analysis,
            'detailed_analysis': response.text,
            'analysis_time': analysis_time
        }

        return analysis_result

    except Exception as e:
        return {
            'error': str(e),
            'analysis': 'Analysis failed due to an error',
            'analysis_time': 0
        }

# [Rest of the code remains the same]
