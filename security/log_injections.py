# security/log_injections.py
import re
from fastapi import HTTPException, Request, Response
import logging
from server.routes.log_routes import log_audit

class InjectionDetector:
    """Regexes for injection detection"""

    @staticmethod
    def detect_sql_injection(text):
        patterns = [
            "' OR '",
            " OR 1=1",
            "--",
            "UNION SELECT",
            "DROP TABLE",
            "DROP DATABASE",
        ]
        print(f"Detecting SQL injection in text: {text}")
        for pattern in patterns:
            if pattern.lower() in text.lower():
                return True, pattern
        return False, None

    @staticmethod
    def detect_xss_injection(text):
        patterns = [
            "<script",
            "onerror=",
            "javascript:",
            "<iframe",
            "<img",
        ]
        for pattern in patterns:
            if pattern.lower() in text.lower():
                return True, pattern
        return False, None

    @staticmethod
    def detect_path_traversal(text):
        patterns = [
            "../",
            "..\\",
            "%2e%2e",
        ]
        for pattern in patterns:
            if pattern.lower() in text.lower():
                return True, pattern
        return False, None
    
class InjectionError(Exception):
    def __init__(self, message: str):
        self.message = message

def detect_and_log_injection(value, field_name, request):
    detect_and_log_injection_cases(value, field_name, request, "Invalid input", noJson=False)

def detect_and_log_injection_login_input(value, field_name, request):
    detect_and_log_injection_cases(value, field_name, request, "Login Failed: Invalid credentials or server error.")

def detect_and_log_injection_register_input(value, field_name, request):
    detect_and_log_injection_cases(value, field_name, request, "Registration Failed: Invalid input.", noJson=False)

def detect_and_log_injection_appoint_input(value, field_name, request):
    detect_and_log_injection_cases(value, field_name, request, "Doctor not found", noJson=False)

def detect_and_log_injection_cases(value, field_name, request, exception_text, noJson=True):
    """Detection of injections"""
    # print("Detecting injections for value:", value)
    sql_injection_detected, sql_pattern = InjectionDetector.detect_sql_injection(value)
    xss_injection_detected, xss_pattern = InjectionDetector.detect_xss_injection(value)
    path_traversal_detected, path_pattern = InjectionDetector.detect_path_traversal(value)

    if sql_injection_detected:
        log_audit(
            "INJECTION_ATTEMPT",
            logging.CRITICAL,
            attack_type="SQL_INJECTION",
            payload=value,
            pattern=sql_pattern,
            ip=request.client.host,
            result=f"FAILED - Connection blocked (SQL Injection): {sql_pattern}",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            field=field_name
        )
        if noJson:
            raise InjectionError(exception_text)
        else:
            raise HTTPException(400, exception_text)
    
    if xss_injection_detected:
        log_audit(
            "INJECTION_ATTEMPT",
            logging.CRITICAL,
            attack_type="XSS_INJECTION",
            payload=value,
            pattern=xss_pattern,
            ip=request.client.host,
            result=f"FAILED - Connection blocked (XSS Injection): {xss_pattern}",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            field=field_name
        )
        if noJson:
            raise InjectionError(exception_text)
        else:
            raise HTTPException(400, exception_text)
    
    if path_traversal_detected:
        log_audit(
            "INJECTION_ATTEMPT",
            logging.CRITICAL,
            attack_type="PATH_TRAVERSAL",
            payload=value,
            pattern=path_pattern,
            ip=request.client.host,
            result=f"FAILED - Connection blocked (Path Traversal): {path_pattern}",
            user_agent=request.headers.get("user-agent"),
            method=request.method,
            path=request.url.path,
            field=field_name
        )
        if noJson:
            raise InjectionError(exception_text)
        else:
            raise HTTPException(400, exception_text)