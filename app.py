def detect_ai_patterns(headers, header_text):
    """Enhanced detection of AI-generated headers with improved pattern recognition"""
    ai_indicators = []
    confidence_factors = []
    
    # 1. Message-ID Analysis
    message_id = headers.get('Message-ID', '')
    if message_id:
        # Check for automated naming patterns
        if re.search(r'(promo|marketing|campaign|auto|mail)-\d{8}-\d+@', message_id):
            ai_indicators.append("AI-typical Message-ID format detected")
            confidence_factors.append(0.8)
        
        # Check for timestamp-based IDs
        current_date = datetime.now()
        date_matches = re.findall(r'(\d{8})', message_id)
        for date_str in date_matches:
            try:
                msg_date = datetime.strptime(date_str, '%Y%m%d')
                if msg_date > current_date:
                    ai_indicators.append("Future date in Message-ID")
                    confidence_factors.append(0.95)
            except ValueError:
                continue
    
    # 2. Advanced Header Pattern Analysis
    marketing_headers = {
        'X-Campaign-ID': 0.7,
        'X-Tracking-ID': 0.6,
        'List-Unsubscribe': 0.4,
        'Precedence': 0.3,
        'X-Mailer': 0.5
    }
    
    marketing_score = 0
    present_marketing_headers = 0
    for header, weight in marketing_headers.items():
        if header in headers:
            marketing_score += weight
            present_marketing_headers += 1
    
    if present_marketing_headers >= 3:
        normalized_score = marketing_score / present_marketing_headers
        ai_indicators.append(f"Marketing automation headers detected (Score: {normalized_score:.2f})")
        confidence_factors.append(normalized_score)
    
    # 3. Timing Analysis
    received_headers = headers.get_all('Received', [])
    if received_headers:
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
        
        if len(timestamps) >= 2:
            time_diffs = [(timestamps[i] - timestamps[i+1]).total_seconds() 
                         for i in range(len(timestamps)-1)]
            
            # Check for suspicious patterns
            if time_diffs:
                # Too uniform timing
                if len(set(int(diff) for diff in time_diffs)) == 1:
                    ai_indicators.append("Suspiciously uniform server processing times")
                    confidence_factors.append(0.9)
                
                # Unrealistic processing speed
                if any(0 < diff < 1.0 for diff in time_diffs):
                    ai_indicators.append("Unrealistically fast server processing")
                    confidence_factors.append(0.95)
                
                # Too perfect progression
                if all(abs(time_diffs[i] - time_diffs[i+1]) < 0.1 for i in range(len(time_diffs)-1)):
                    ai_indicators.append("Too perfect timing progression")
                    confidence_factors.append(0.85)
    
    # 4. Content Consistency Analysis
    domains = re.findall(r'@([\w.-]+)', header_text)
    unique_domains = set(domains)
    
    if len(domains) > 3 and len(unique_domains) == 1:
        ai_indicators.append("Suspiciously consistent domain usage across headers")
        confidence_factors.append(0.75)
    
    # 5. Authentication Pattern Analysis
    auth_results = headers.get('Authentication-Results', '')
    dkim_sig = headers.get('DKIM-Signature', '')
    
    if auth_results and dkim_sig:
        # Check for too-perfect authentication
        if ('dkim=pass' in auth_results.lower() and 
            'spf=pass' in auth_results.lower() and
            re.search(r'v=1;\s*a=rsa-sha256;\s*c=relaxed/relaxed', dkim_sig)):
            
            ai_indicators.append("Suspiciously perfect authentication setup")
            confidence_factors.append(0.6)
    
    # 6. Header Structure Analysis
    required_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
    optional_headers = ['Reply-To', 'Return-Path', 'X-Mailer']
    
    present_required = sum(1 for h in required_headers if h in headers)
    present_optional = sum(1 for h in optional_headers if h in headers)
    
    if present_required == len(required_headers) and present_optional >= 2:
        header_format_score = 0
        for header in headers.items():
            if re.match(r'^[A-Za-z-]+: .+$', str(header)):
                header_format_score += 1
        
        if header_format_score / len(list(headers.items())) > 0.95:
            ai_indicators.append("Unusually perfect header formatting and completeness")
            confidence_factors.append(0.7)
    
    # 7. Date Pattern Analysis
    date_str = headers.get('Date', '')
    if date_str:
        try:
            email_date = parsedate_to_datetime(date_str)
            now = datetime.now()
            
            # Check future dates
            if email_date > now + timedelta(days=1):
                ai_indicators.append("Email date is in the future")
                confidence_factors.append(0.95)
            
            # Check round-number timestamps
            if email_date.second == 0 and email_date.microsecond == 0:
                ai_indicators.append("Suspiciously round timestamp")
                confidence_factors.append(0.4)
        except (ValueError, TypeError):
            pass
    
    # 8. Machine-Generated Content Indicators
    mailer = headers.get('X-Mailer', '')
    if mailer:
        if re.search(r'(Marketing|Campaign|Promo|Auto|Bot|Suite)\s+v?\d+\.\d+', mailer, re.I):
            ai_indicators.append("Automated marketing system signature detected")
            confidence_factors.append(0.65)
    
    # Calculate weighted AI probability
    weights = [0.8, 0.9, 0.7, 0.6, 0.8, 0.7, 0.9, 0.6]  # Weights for different types of checks
    if confidence_factors:
        weighted_scores = [cf * w for cf, w in zip(confidence_factors, weights[:len(confidence_factors)])]
        ai_probability = min(sum(weighted_scores) / sum(weights[:len(confidence_factors)]), 1.0) * 100
    else:
        ai_probability = 0
    
    return {
        'indicators': ai_indicators,
        'probability': round(ai_probability, 2),
        'confidence_factors': confidence_factors,
        'indicator_count': len(ai_indicators)
    }
