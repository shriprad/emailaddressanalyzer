import os
import time
import re
import base64
import google.generativeai as genai
from flask import Flask, render_template_string, request, jsonify
from email import parser, policy
import dkim
import spf
from datetime import datetime

app = Flask(__name__)

# Configure Gemini AI
os.environ['GOOGLE_API_KEY'] = 'YOUR_API_KEY_HERE'
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Header Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-6xl mx-auto">
        <h1 class="text-3xl font-bold mb-8">Email Header Analyzer</h1>
        
        <form method="POST" class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
            <div class="mb-4">
                <label class="block text-gray-700 text-sm font-bold mb-2" for="headers">
                    Paste Email Headers:
                </label>
                <textarea
                    class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    id="headers"
                    name="headers"
                    rows="10"
                    required
                >{{ request.form.get('headers', '') }}</textarea>
            </div>
            
            <div class="flex items-center justify-between">
                <button
                    class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    type="submit"
                    name="analyze"
                >
                    Analyze Headers
                </button>
                <button
                    class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    type="submit"
                    name="redact"
                >
                    Redact Sensitive Info
                </button>
            </div>
        </form>

        {% if redacted_headers %}
        <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
            <h2 class="text-xl font-bold mb-4">Redacted Headers</h2>
            <pre class="bg-gray-100 p-4 rounded overflow-x-auto">{{ redacted_headers }}</pre>
        </div>
        {% endif %}

        {% if analysis_result %}
        <div class="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
            <h2 class="text-xl font-bold mb-4">Analysis Results</h2>
            
            {% if analysis_result.error %}
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
                <strong class="font-bold">Error:</strong>
                <span class="block sm:inline">{{ analysis_result.error }}</span>
            </div>
            {% else %}
            
            <div class="mb-6">
                <h3 class="text-lg font-semibold mb-2">Authentication Analysis</h3>
                <div class="bg-gray-100 p-4 rounded">
                    <p><strong>DKIM Present:</strong> {{ analysis_result.auth_analysis.dkim_present }}</p>
                    <p><strong>SPF Present:</strong> {{ analysis_result.auth_analysis.spf_present }}</p>
                    <p><strong>Authentication Results:</strong> {{ analysis_result.auth_analysis.auth_results }}</p>
                </div>
            </div>

            <div class="mb-6">
                <h3 class="text-lg font-semibold mb-2">AI Pattern Indicators</h3>
                <div class="bg-gray-100 p-4 rounded">
                    <ul class="list-disc pl-4">
                    {% for indicator in analysis_result.ai_indicators %}
                        <li>{{ indicator }}</li>
                    {% endfor %}
                    </ul>
                </div>
            </div>

            <div class="mb-6">
                <h3 class="text-lg font-semibold mb-2">Detailed Analysis</h3>
                <div class="bg-gray-100 p-4 rounded whitespace-pre-wrap">
                    {{ analysis_result.detailed_analysis }}
                </div>
            </div>

            <div class="text-sm text-gray-600">
                Analysis completed in {{ analysis_result.analysis_time }} seconds
            </div>
            {% endif %}
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

def redact_sensitive_info(text):
    """Redact email addresses, ESMTP IDs, and other sensitive information"""
    # Redact email addresses
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    
    # Redact ESMTP IDs (various formats)
    text = re.sub(r'(?i)id\s+[A-Za-z0-9-]+', 'id [REDACTED_ESMTP_ID]', text)
    
    # Redact IP addresses
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', text)
    
    # Redact Message-IDs
    text = re.sub(r'<[\w\.-]+@[\w\.-]+>', '[REDACTED_MESSAGE_ID]', text)
    
    return text

def parse_header_structure(headers):
    """Extract and structure email headers"""
    parsed_headers = {}
    
    # Extract key header fields
    important_fields = [
        'From', 'To', 'Subject', 'Date', 'Received', 'Message-ID',
        'DKIM-Signature', 'SPF', 'Authentication-Results',
        'X-Originating-IP', 'X-Mailer', 'User-Agent'
    ]
    
    for field in important_fields:
        value = headers.get(field)
        if value:
            if isinstance(value, list):
                parsed_headers[field] = [str(v) for v in value]
            else:
                parsed_headers[field] = str(value)
    
    return parsed_headers

def analyze_authentication(headers):
    """Analyze email authentication mechanisms"""
    auth_results = {
        'dkim_present': 'DKIM-Signature' in headers,
        'spf_present': 'Received-SPF' in headers or 'SPF' in headers,
        'auth_results': headers.get('Authentication-Results', 'Not found')
    }
    
    return auth_results

def analyze_routing(headers):
    """Analyze email routing path and timestamps"""
    received_headers = headers.get_all('Received', [])
    routing_analysis = []
    
    for header in received_headers:
        try:
            # Extract timestamps and server information
            timestamp_match = re.search(r';(.*?)(?:\(.*?\))?\s*$', header)
            server_match = re.search(r'from\s+(.*?)\s+by', header)
            
            if timestamp_match:
                timestamp = timestamp_match.group(1).strip()
                server = server_match.group(1) if server_match else 'Unknown'
                
                routing_analysis.append({
                    'server': server,
                    'timestamp': timestamp
                })
        except Exception as e:
            continue
    
    return routing_analysis

def detect_ai_patterns(headers):
    """Detect patterns that might indicate AI-generated headers"""
    ai_indicators = []
    
    # Check for unusual patterns in Message-ID
    message_id = headers.get('Message-ID', '')
    if message_id:
        if re.search(r'[A-Za-z0-9]{32,}', message_id):
            ai_indicators.append("Unusually long or random Message-ID")
    
    # Check for inconsistent timestamps
    received_headers = headers.get_all('Received', [])
    timestamps = []
    for header in received_headers:
        timestamp_match = re.search(r';(.*?)(?:\(.*?\))?\s*$', header)
        if timestamp_match:
            try:
                timestamp = datetime.strptime(timestamp_match.group(1).strip(), '%a, %d %b %Y %H:%M:%S %z')
                timestamps.append(timestamp)
            except ValueError:
                continue
    
    if timestamps:
        time_diffs = [(timestamps[i] - timestamps[i+1]).total_seconds() for i in range(len(timestamps)-1)]
        if any(diff < 0 for diff in time_diffs):
            ai_indicators.append("Inconsistent timestamp sequence")
        if any(diff < 1 for diff in time_diffs):
            ai_indicators.append("Unrealistic timing between servers")
    
    return ai_indicators

def analyze_headers(header_text):
    try:
        # Parse the email headers
        parser_instance = parser.HeaderParser(policy=policy.default)
        headers = parser_instance.parsestr(header_text)
        
        # Extract structured header information
        parsed_headers = parse_header_structure(headers)
        
        # Analyze authentication
        auth_analysis = analyze_authentication(headers)
        
        # Analyze routing
        routing_analysis = analyze_routing(headers)
        
        # Detect AI patterns
        ai_indicators = detect_ai_patterns(headers)
        
        # Prepare analysis prompt for Gemini AI
        analysis_prompt = f"""Analyze these email headers for potential spoofing and suspicious patterns:

        Parsed Headers:
        {parsed_headers}

        Authentication Analysis:
        - DKIM Present: {auth_analysis['dkim_present']}
        - SPF Present: {auth_analysis['spf_present']}
        - Authentication Results: {auth_analysis['auth_results']}

        Routing Analysis:
        {routing_analysis}

        AI Pattern Indicators:
        {ai_indicators}

        Please provide a comprehensive security analysis including:

        1. Authentication Assessment:
        - Evaluate DKIM, SPF, and DMARC status
        - Identify any authentication failures or inconsistencies
        
        2. Routing Analysis:
        - Evaluate the email's path through servers
        - Identify suspicious routing patterns
        - Flag any timing inconsistencies
        
        3. Header Structure Analysis:
        - Identify missing or suspicious headers
        - Analyze header formatting and consistency
        - Flag unusual or non-standard header fields
        
        4. AI Generation Indicators:
        - Assess likelihood of AI-generated headers
        - Identify specific suspicious patterns
        - Provide confidence level of AI generation
        
        5. Spoofing Risk Assessment:
        - Calculate spoofing probability (0-100%)
        - Assign risk level (Low/Medium/High)
        - List specific security concerns
        - Provide detailed justification
        
        6. Security Recommendations:
        - Specific actions if suspicious
        - Best practices for verification
        - Additional checks recommended

        Format the response clearly with section headers and bullet points.
        """

        # Get Gemini AI analysis
        model = genai.GenerativeModel('gemini-pro')
        start_time = time.time()
        response = model.generate_content(analysis_prompt)
        analysis_time = round(time.time() - start_time, 2)

        # Prepare the result
        analysis_result = {
            'parsed_headers': parsed_headers,
            'auth_analysis': auth_analysis,
            'routing_analysis': routing_analysis,
            'ai_indicators': ai_indicators,
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

@app.route("/", methods=["GET", "POST"])
def index():
    analysis_result = None
    redacted_headers = None
    
    if request.method == "POST":
        headers = request.form.get("headers")
        if headers:
            if 'analyze' in request.form:
                analysis_result = analyze_headers(headers)
            elif 'redact' in request.form:
                redacted_headers = redact_sensitive_info(headers)
    
    return render_template_string(HTML_TEMPLATE, 
                                analysis_result=analysis_result,
                                redacted_headers=redacted_headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)