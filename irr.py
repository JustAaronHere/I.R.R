#!/usr/bin/env python3
"""
IRR - Incident Readiness & Response Evaluator
A modular cybersecurity assessment platform for evaluating incident response readiness
"""

import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import re


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

class Color:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Standard colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'


class ReadinessLevel(Enum):
    """Incident response readiness classification"""
    CRITICAL = "Critical"
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    EXCELLENT = "Excellent"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class EnvironmentProfile:
    """Organization environment metadata"""
    org_name: str
    platforms: List[str]
    endpoints_count: int
    network_segments: List[str]
    security_tools: List[str]
    log_sources: List[str]
    retention_days: int
    timestamp: str = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class LogAnalysisResult:
    """Results from log availability and quality analysis"""
    source_name: str
    available: bool
    retention_compliance: bool
    timestamp_consistency: float
    volume_score: float
    completeness_score: float
    issues: List[str]
    recommendations: List[str]


@dataclass
class PlaybookAnalysisResult:
    """Results from playbook evaluation"""
    playbook_name: str
    clarity_score: float
    feasibility_score: float
    completeness_score: float
    ambiguous_steps: List[str]
    missing_elements: List[str]
    unrealistic_assumptions: List[str]
    recommendations: List[str]


@dataclass
class ReadinessAssessment:
    """Overall incident response readiness assessment"""
    overall_score: float
    readiness_level: str
    evidence_availability: float
    timeline_reconstruction: float
    playbook_effectiveness: float
    policy_alignment: float
    critical_gaps: List[str]
    high_priority_gaps: List[str]
    medium_priority_gaps: List[str]
    recommendations: List[str]
    timestamp: str = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def clear_screen():
    """Clear terminal screen cross-platform"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Display professional ASCII banner"""
    banner = f"""
{Color.CYAN}{Color.BOLD}
██╗██████╗ ██████╗ 
██║██╔══██╗██╔══██╗
██║██████╔╝██████╔╝
██║██╔══██╗██╔══██╗
██║██║  ██║██║  ██║
╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{Color.RESET}
{Color.WHITE}{Color.BOLD}Incident Readiness & Response Evaluator{Color.RESET}
{Color.DIM}Professional Security Assessment Platform v1.0{Color.RESET}
{Color.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Color.RESET}
"""
    print(banner)


def print_section_header(title: str):
    """Print formatted section header"""
    print(f"\n{Color.CYAN}{Color.BOLD}{'='*60}{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}{title.center(60)}{Color.RESET}")
    print(f"{Color.CYAN}{Color.BOLD}{'='*60}{Color.RESET}\n")


def print_success(message: str):
    """Print success message"""
    print(f"{Color.GREEN}✓{Color.RESET} {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Color.YELLOW}⚠{Color.RESET} {message}")


def print_error(message: str):
    """Print error message"""
    print(f"{Color.RED}✗{Color.RESET} {message}")


def print_info(message: str):
    """Print info message"""
    print(f"{Color.BLUE}ℹ{Color.RESET} {message}")


def get_input(prompt: str, default: str = None) -> str:
    """Get user input with optional default"""
    if default:
        full_prompt = f"{Color.WHITE}{prompt}{Color.RESET} [{Color.DIM}{default}{Color.RESET}]: "
    else:
        full_prompt = f"{Color.WHITE}{prompt}{Color.RESET}: "
    
    value = input(full_prompt).strip()
    return value if value else default


def get_yes_no(prompt: str, default: bool = True) -> bool:
    """Get yes/no confirmation from user"""
    default_str = "Y/n" if default else "y/N"
    response = get_input(f"{prompt} ({default_str})", "y" if default else "n").lower()
    return response in ['y', 'yes', '1', 'true'] if response else default


def display_menu(title: str, options: List[str]) -> int:
    """Display menu and get user selection"""
    print(f"\n{Color.BOLD}{title}{Color.RESET}")
    print(f"{Color.DIM}{'─'*60}{Color.RESET}")
    
    for i, option in enumerate(options, 1):
        print(f"  {Color.CYAN}{i}.{Color.RESET} {option}")
    
    print(f"  {Color.CYAN}0.{Color.RESET} {Color.DIM}Exit{Color.RESET}")
    print()
    
    while True:
        try:
            choice = int(get_input("Select option", "1"))
            if 0 <= choice <= len(options):
                return choice
            print_error(f"Please enter a number between 0 and {len(options)}")
        except ValueError:
            print_error("Please enter a valid number")


def display_progress_bar(current: int, total: int, prefix: str = "Progress"):
    """Display progress bar"""
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = '█' * filled + '░' * (bar_length - filled)
    percent = int(100 * current / total)
    
    print(f"\r{prefix}: {Color.CYAN}[{bar}]{Color.RESET} {percent}%", end='', flush=True)
    
    if current == total:
        print()


# ============================================================================
# MODULE: ENVIRONMENT OVERVIEW
# ============================================================================

class EnvironmentModule:
    """Module for collecting and analyzing environment metadata"""
    
    def __init__(self):
        self.profile: Optional[EnvironmentProfile] = None
    
    def collect_environment_data(self) -> EnvironmentProfile:
        """Interactive collection of environment metadata"""
        print_section_header("ENVIRONMENT OVERVIEW")
        
        print_info("Collect organizational security environment metadata")
        print(f"{Color.DIM}This information helps contextualize the readiness assessment.{Color.RESET}\n")
        
        org_name = get_input("Organization name", "My Organization")
        
        print(f"\n{Color.BOLD}Platform Coverage:{Color.RESET}")
        print(f"{Color.DIM}Enter platforms (comma-separated): Windows, Linux, macOS, Cloud, etc.{Color.RESET}")
        platforms = [p.strip() for p in get_input("Platforms", "Windows,Linux").split(',')]
        
        endpoints_count = int(get_input("Approximate endpoint count", "100"))
        
        print(f"\n{Color.BOLD}Network Architecture:{Color.RESET}")
        print(f"{Color.DIM}Enter network segments (comma-separated): DMZ, Internal, Management, etc.{Color.RESET}")
        network_segments = [s.strip() for s in get_input("Network segments", "DMZ,Internal").split(',')]
        
        print(f"\n{Color.BOLD}Security Tools:{Color.RESET}")
        print(f"{Color.DIM}Enter security tools (comma-separated): EDR, SIEM, Firewall, etc.{Color.RESET}")
        security_tools = [t.strip() for t in get_input("Security tools", "EDR,SIEM,Firewall").split(',')]
        
        print(f"\n{Color.BOLD}Log Sources:{Color.RESET}")
        print(f"{Color.DIM}Enter log sources (comma-separated): Windows Event Logs, Syslog, Application Logs, etc.{Color.RESET}")
        log_sources = [l.strip() for l in get_input("Log sources", "Windows Event Logs,Syslog").split(',')]
        
        retention_days = int(get_input("Log retention period (days)", "90"))
        
        self.profile = EnvironmentProfile(
            org_name=org_name,
            platforms=platforms,
            endpoints_count=endpoints_count,
            network_segments=network_segments,
            security_tools=security_tools,
            log_sources=log_sources,
            retention_days=retention_days
        )
        
        print_success("Environment profile collected successfully")
        return self.profile
    
    def display_environment_summary(self):
        """Display collected environment information"""
        if not self.profile:
            print_warning("No environment data collected yet")
            return
        
        print_section_header("ENVIRONMENT SUMMARY")
        
        print(f"{Color.BOLD}Organization:{Color.RESET} {self.profile.org_name}")
        print(f"{Color.BOLD}Endpoints:{Color.RESET} {self.profile.endpoints_count:,}")
        print(f"{Color.BOLD}Log Retention:{Color.RESET} {self.profile.retention_days} days")
        
        print(f"\n{Color.BOLD}Platforms:{Color.RESET}")
        for platform in self.profile.platforms:
            print(f"  • {platform}")
        
        print(f"\n{Color.BOLD}Network Segments:{Color.RESET}")
        for segment in self.profile.network_segments:
            print(f"  • {segment}")
        
        print(f"\n{Color.BOLD}Security Tools:{Color.RESET}")
        for tool in self.profile.security_tools:
            print(f"  • {tool}")
        
        print(f"\n{Color.BOLD}Log Sources:{Color.RESET}")
        for source in self.profile.log_sources:
            print(f"  • {source}")


# ============================================================================
# MODULE: LOG ANALYSIS
# ============================================================================

class LogAnalysisModule:
    """Module for analyzing log availability, quality, and completeness"""
    
    def __init__(self, environment: EnvironmentModule):
        self.environment = environment
        self.results: List[LogAnalysisResult] = []
    
    def analyze_logs(self) -> List[LogAnalysisResult]:
        """Analyze log sources for incident response readiness"""
        print_section_header("LOG ANALYSIS")
        
        if not self.environment.profile:
            print_error("Environment profile must be collected first")
            return []
        
        print_info("Analyzing log sources for incident response capabilities...")
        print()
        
        self.results = []
        log_sources = self.environment.profile.log_sources
        
        for i, source in enumerate(log_sources, 1):
            display_progress_bar(i, len(log_sources), "Analyzing")
            result = self._analyze_log_source(source)
            self.results.append(result)
        
        print("\n")
        self._display_analysis_results()
        return self.results
    
    def _analyze_log_source(self, source: str) -> LogAnalysisResult:
        """Analyze individual log source"""
        # Simulate comprehensive analysis
        issues = []
        recommendations = []
        
        # Determine availability based on source type
        available = True
        
        # Check retention compliance
        retention_compliance = self.environment.profile.retention_days >= 90
        if not retention_compliance:
            issues.append(f"Retention period ({self.environment.profile.retention_days} days) below recommended 90 days")
            recommendations.append("Increase log retention to at least 90 days")
        
        # Analyze timestamp consistency (simulated scoring)
        timestamp_consistency = 0.85 if "Windows" in source or "Syslog" in source else 0.75
        if timestamp_consistency < 0.9:
            issues.append("Potential timestamp synchronization issues detected")
            recommendations.append("Implement NTP synchronization across all log sources")
        
        # Volume and completeness scoring
        volume_score = 0.80
        completeness_score = 0.75
        
        if "Application" in source or "Custom" in source:
            completeness_score = 0.65
            issues.append("Application logs may lack critical security events")
            recommendations.append("Enhance application logging to include authentication and authorization events")
        
        return LogAnalysisResult(
            source_name=source,
            available=available,
            retention_compliance=retention_compliance,
            timestamp_consistency=timestamp_consistency,
            volume_score=volume_score,
            completeness_score=completeness_score,
            issues=issues,
            recommendations=recommendations
        )
    
    def _display_analysis_results(self):
        """Display log analysis results"""
        print(f"{Color.BOLD}Log Analysis Results:{Color.RESET}\n")
        
        for result in self.results:
            status = f"{Color.GREEN}✓ Available{Color.RESET}" if result.available else f"{Color.RED}✗ Unavailable{Color.RESET}"
            print(f"{Color.BOLD}{result.source_name}{Color.RESET} - {status}")
            print(f"  Timestamp Consistency: {self._score_to_color(result.timestamp_consistency)}")
            print(f"  Volume Score: {self._score_to_color(result.volume_score)}")
            print(f"  Completeness: {self._score_to_color(result.completeness_score)}")
            
            if result.issues:
                print(f"  {Color.YELLOW}Issues:{Color.RESET}")
                for issue in result.issues:
                    print(f"    • {issue}")
            print()
    
    def _score_to_color(self, score: float) -> str:
        """Convert score to colored display"""
        percentage = int(score * 100)
        if score >= 0.9:
            color = Color.GREEN
        elif score >= 0.75:
            color = Color.YELLOW
        else:
            color = Color.RED
        return f"{color}{percentage}%{Color.RESET}"
    
    def get_evidence_availability_score(self) -> float:
        """Calculate overall evidence availability score"""
        if not self.results:
            return 0.0
        
        scores = [
            (r.timestamp_consistency + r.volume_score + r.completeness_score) / 3
            for r in self.results
        ]
        return sum(scores) / len(scores)


# ============================================================================
# MODULE: PLAYBOOK EVALUATION
# ============================================================================

class PlaybookModule:
    """Module for evaluating incident response playbooks"""
    
    def __init__(self):
        self.results: List[PlaybookAnalysisResult] = []
    
    def evaluate_playbooks(self) -> List[PlaybookAnalysisResult]:
        """Evaluate incident response playbooks"""
        print_section_header("PLAYBOOK EVALUATION")
        
        print_info("Evaluating incident response playbook effectiveness...")
        print(f"{Color.DIM}Analyzing clarity, feasibility, and completeness of response procedures.{Color.RESET}\n")
        
        # Common incident types
        playbook_types = [
            "Malware Infection Response",
            "Phishing Incident Response",
            "Data Breach Response",
            "Ransomware Response",
            "Insider Threat Response",
            "DDoS Attack Response"
        ]
        
        print(f"{Color.BOLD}Standard Playbooks to Evaluate:{Color.RESET}")
        for i, pb in enumerate(playbook_types, 1):
            print(f"  {i}. {pb}")
        print()
        
        if get_yes_no("Evaluate standard playbooks"):
            for i, playbook in enumerate(playbook_types, 1):
                display_progress_bar(i, len(playbook_types), "Evaluating")
                result = self._evaluate_playbook(playbook)
                self.results.append(result)
            print("\n")
        
        # Custom playbooks
        if get_yes_no("Evaluate custom playbooks", False):
            while True:
                playbook_name = get_input("Custom playbook name (or 'done' to finish)")
                if playbook_name.lower() == 'done':
                    break
                result = self._evaluate_playbook(playbook_name)
                self.results.append(result)
                print_success(f"Evaluated: {playbook_name}\n")
        
        if self.results:
            self._display_evaluation_results()
        
        return self.results
    
    def _evaluate_playbook(self, playbook_name: str) -> PlaybookAnalysisResult:
        """Evaluate individual playbook"""
        # Simulate comprehensive evaluation
        ambiguous_steps = []
        missing_elements = []
        unrealistic_assumptions = []
        recommendations = []
        
        # Baseline scores
        clarity_score = 0.75
        feasibility_score = 0.70
        completeness_score = 0.72
        
        # Identify common issues
        if "Malware" in playbook_name or "Ransomware" in playbook_name:
            ambiguous_steps.append("Step 5: 'Contain the threat' lacks specific isolation procedures")
            missing_elements.append("No guidance on encrypted backup restoration")
            recommendations.append("Add detailed network isolation procedures with specific commands")
            clarity_score -= 0.05
            completeness_score -= 0.08
        
        if "Phishing" in playbook_name:
            ambiguous_steps.append("Step 3: 'Analyze email headers' assumes technical expertise")
            missing_elements.append("Missing user communication templates")
            recommendations.append("Include step-by-step header analysis guide with examples")
            clarity_score -= 0.10
        
        if "Data Breach" in playbook_name:
            unrealistic_assumptions.append("Assumes full network visibility and logging")
            missing_elements.append("Legal and regulatory notification procedures undefined")
            recommendations.append("Develop breach notification checklist with timelines")
            feasibility_score -= 0.15
            completeness_score -= 0.12
        
        # Common gaps across all playbooks
        if not missing_elements:
            missing_elements.append("Documentation requirements not specified")
        
        recommendations.append("Conduct tabletop exercise to validate procedures")
        recommendations.append("Define clear roles and escalation criteria")
        
        return PlaybookAnalysisResult(
            playbook_name=playbook_name,
            clarity_score=max(0.0, clarity_score),
            feasibility_score=max(0.0, feasibility_score),
            completeness_score=max(0.0, completeness_score),
            ambiguous_steps=ambiguous_steps,
            missing_elements=missing_elements,
            unrealistic_assumptions=unrealistic_assumptions,
            recommendations=recommendations
        )
    
    def _display_evaluation_results(self):
        """Display playbook evaluation results"""
        print(f"\n{Color.BOLD}Playbook Evaluation Results:{Color.RESET}\n")
        
        for result in self.results:
            overall = (result.clarity_score + result.feasibility_score + result.completeness_score) / 3
            
            print(f"{Color.BOLD}{result.playbook_name}{Color.RESET}")
            print(f"  Overall Effectiveness: {self._score_to_color(overall)}")
            print(f"  Clarity: {self._score_to_color(result.clarity_score)}")
            print(f"  Feasibility: {self._score_to_color(result.feasibility_score)}")
            print(f"  Completeness: {self._score_to_color(result.completeness_score)}")
            
            if result.ambiguous_steps:
                print(f"  {Color.YELLOW}Ambiguous Steps:{Color.RESET}")
                for step in result.ambiguous_steps[:2]:  # Limit display
                    print(f"    • {step}")
            
            if result.missing_elements:
                print(f"  {Color.RED}Missing Elements:{Color.RESET}")
                for element in result.missing_elements[:2]:
                    print(f"    • {element}")
            print()
    
    def _score_to_color(self, score: float) -> str:
        """Convert score to colored display"""
        percentage = int(score * 100)
        if score >= 0.8:
            color = Color.GREEN
        elif score >= 0.65:
            color = Color.YELLOW
        else:
            color = Color.RED
        return f"{color}{percentage}%{Color.RESET}"
    
    def get_playbook_effectiveness_score(self) -> float:
        """Calculate overall playbook effectiveness"""
        if not self.results:
            return 0.0
        
        scores = [
            (r.clarity_score + r.feasibility_score + r.completeness_score) / 3
            for r in self.results
        ]
        return sum(scores) / len(scores)


# ============================================================================
# MODULE: POLICY & TOOL READINESS
# ============================================================================

class PolicyToolModule:
    """Module for evaluating security policies and tool readiness"""
    
    def __init__(self, environment: EnvironmentModule):
        self.environment = environment
        self.policy_score = 0.0
        self.tool_score = 0.0
        self.bottlenecks: List[str] = []
        self.recommendations: List[str] = []
    
    def evaluate_readiness(self) -> Dict[str, Any]:
        """Evaluate policy and tool readiness"""
        print_section_header("POLICY & TOOL READINESS")
        
        print_info("Evaluating security policies and tool effectiveness...")
        print()
        
        self._evaluate_policies()
        self._evaluate_tools()
        self._identify_bottlenecks()
        
        self._display_results()
        
        return {
            'policy_score': self.policy_score,
            'tool_score': self.tool_score,
            'bottlenecks': self.bottlenecks,
            'recommendations': self.recommendations
        }
    
    def _evaluate_policies(self):
        """Evaluate security policies"""
        print(f"{Color.BOLD}Policy Assessment:{Color.RESET}\n")
        
        policies = [
            ("Incident Response Policy", "Formal documented procedures for incident handling"),
            ("Escalation Policy", "Clear escalation paths and approval thresholds"),
            ("Communication Policy", "Internal and external communication protocols"),
            ("Data Handling Policy", "Evidence collection and preservation guidelines"),
            ("Access Control Policy", "Emergency access and privilege escalation procedures")
        ]
        
        policy_scores = []
        for policy_name, description in policies:
            exists = get_yes_no(f"  {policy_name} exists and is current")
            if exists:
                documented = get_yes_no(f"    Is it well-documented and accessible")
                tested = get_yes_no(f"    Has it been tested in the last 12 months")
                
                score = 0.5 + (0.25 if documented else 0) + (0.25 if tested else 0)
                policy_scores.append(score)
                
                if not tested:
                    self.recommendations.append(f"Conduct tabletop exercise for {policy_name}")
            else:
                policy_scores.append(0.0)
                self.recommendations.append(f"Develop and document {policy_name}")
            print()
        
        self.policy_score = sum(policy_scores) / len(policy_scores) if policy_scores else 0.0
    
    def _evaluate_tools(self):
        """Evaluate security tool effectiveness"""
        print(f"\n{Color.BOLD}Tool Effectiveness Assessment:{Color.RESET}\n")
        
        if not self.environment.profile:
            self.tool_score = 0.0
            return
        
        tools = self.environment.profile.security_tools
        tool_scores = []
        
        for tool in tools:
            print(f"{Color.BOLD}{tool}:{Color.RESET}")
            
            operational = get_yes_no(f"  Fully operational and monitored")
            integrated = get_yes_no(f"  Integrated with incident response workflow")
            
            score = 0.5 if operational else 0.0
            score += 0.3 if integrated else 0.0
            score += 0.2  # Baseline for existence
            
            tool_scores.append(score)
            
            if not integrated:
                self.recommendations.append(f"Integrate {tool} into centralized incident response platform")
            print()
        
        self.tool_score = sum(tool_scores) / len(tool_scores) if tool_scores else 0.0
    
    def _identify_bottlenecks(self):
        """Identify potential response bottlenecks"""
        print(f"{Color.BOLD}Bottleneck Analysis:{Color.RESET}\n")
        
        potential_bottlenecks = [
            ("Manual log correlation", "Requires manual analysis across multiple systems"),
            ("Approval delays", "Critical actions require management approval"),
            ("Tool fragmentation", "No unified incident management platform"),
            ("Expertise gaps", "Limited 24/7 coverage or specialized skills"),
            ("Communication delays", "Stakeholder notification requires manual coordination")
        ]
        
        for bottleneck, description in potential_bottlenecks:
            if get_yes_no(f"  Potential bottleneck: {bottleneck}"):
                self.bottlenecks.append(f"{bottleneck}: {description}")
                
                # Generate specific recommendations
                if "Manual log" in bottleneck:
                    self.recommendations.append("Implement SOAR platform for automated log correlation")
                elif "Approval" in bottleneck:
                    self.recommendations.append("Pre-authorize common response actions for on-call personnel")
                elif "Tool fragmentation" in bottleneck:
                    self.recommendations.append("Deploy unified SIEM/SOAR platform")
                elif "Expertise" in bottleneck:
                    self.recommendations.append("Establish 24/7 SOC coverage or engage MDR provider")
                elif "Communication" in bottleneck:
                    self.recommendations.append("Implement automated stakeholder notification system")
        print()
    
    def _display_results(self):
        """Display policy and tool readiness results"""
        print(f"\n{Color.BOLD}Policy & Tool Readiness Summary:{Color.RESET}\n")
        
        print(f"Policy Maturity: {self._score_to_color(self.policy_score)}")
        print(f"Tool Effectiveness: {self._score_to_color(self.tool_score)}")
        
        if self.bottlenecks:
            print(f"\n{Color.YELLOW}Identified Bottlenecks:{Color.RESET}")
            for bottleneck in self.bottlenecks:
                print(f"  • {bottleneck}")
    
    def _score_to_color(self, score: float) -> str:
        """Convert score to colored display"""
        percentage = int(score * 100)
        if score >= 0.8:
            color = Color.GREEN
        elif score >= 0.65:
            color = Color.YELLOW
        else:
            color = Color.RED
        return f"{color}{percentage}%{Color.RESET}"
    
    def get_policy_alignment_score(self) -> float:
        """Get overall policy alignment score"""
        return (self.policy_score + self.tool_score) / 2


# ============================================================================
# MODULE: SCENARIO TESTING
# ============================================================================

class ScenarioModule:
    """Module for scenario-based readiness testing"""
    
    def __init__(self, environment: EnvironmentModule, log_module: LogAnalysisModule, 
                 playbook_module: PlaybookModule, policy_module: PolicyToolModule):
        self.environment = environment
        self.log_module = log_module
        self.playbook_module = playbook_module
        self.policy_module = policy_module
        self.scenarios: List[Dict[str, Any]] = []
    
    def run_scenario_testing(self) -> List[Dict[str, Any]]:
        """Run scenario-based readiness evaluation"""
        print_section_header("SCENARIO TESTING")
        
        print_info("Evaluate readiness against hypothetical incident scenarios")
        print(f"{Color.DIM}This module tests response capability in realistic situations.{Color.RESET}\n")
        
        if not get_yes_no("Run scenario testing"):
            return []
        
        predefined_scenarios = [
            {
                'name': 'Ransomware Attack',
                'description': 'Multiple endpoints encrypted, ransom note detected',
                'required_logs': ['Windows Event Logs', 'EDR', 'Network Traffic'],
                'required_playbook': 'Ransomware Response',
                'complexity': 'high'
            },
            {
                'name': 'Credential Compromise',
                'description': 'Suspicious login from unusual location detected',
                'required_logs': ['Authentication Logs', 'VPN Logs'],
                'required_playbook': 'Insider Threat Response',
                'complexity': 'medium'
            },
            {
                'name': 'Data Exfiltration',
                'description': 'Large outbound data transfer to unknown destination',
                'required_logs': ['Network Traffic', 'Firewall Logs', 'DLP'],
                'required_playbook': 'Data Breach Response',
                'complexity': 'high'
            }
        ]
        
        print(f"{Color.BOLD}Available Scenarios:{Color.RESET}")
        for i, scenario in enumerate(predefined_scenarios, 1):
            print(f"  {i}. {scenario['name']} - {scenario['description']}")
        print()
        
        selected = get_input("Select scenarios (comma-separated numbers, or 'all')", "all")
        
        if selected.lower() == 'all':
            scenarios_to_test = predefined_scenarios
        else:
            indices = [int(x.strip()) - 1 for x in selected.split(',') if x.strip().isdigit()]
            scenarios_to_test = [predefined_scenarios[i] for i in indices if 0 <= i < len(predefined_scenarios)]
        
        for i, scenario in enumerate(scenarios_to_test, 1):
            display_progress_bar(i, len(scenarios_to_test), "Testing")
            result = self._test_scenario(scenario)
            self.scenarios.append(result)
        
        print("\n")
        self._display_scenario_results()
        
        return self.scenarios
    
    def _test_scenario(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Test readiness for specific scenario"""
        result = {
            'name': scenario['name'],
            'description': scenario['description'],
            'readiness_score': 0.0,
            'log_availability': 0.0,
            'playbook_match': False,
            'timeline_feasibility': 0.0,
            'gaps': [],
            'strengths': []
        }
        
        # Check log availability
        available_logs = [r.source_name for r in self.log_module.results if r.available]
        required_logs = scenario['required_logs']
        
        log_coverage = sum(1 for log in required_logs if any(log.lower() in al.lower() for al in available_logs))
        result['log_availability'] = log_coverage / len(required_logs) if required_logs else 0.0
        
        if result['log_availability'] < 1.0:
            missing_logs = [log for log in required_logs if not any(log.lower() in al.lower() for al in available_logs)]
            result['gaps'].append(f"Missing critical logs: {', '.join(missing_logs)}")
        else:
            result['strengths'].append("All required log sources available")
        
        # Check playbook availability
        playbook_names = [p.playbook_name for p in self.playbook_module.results]
        result['playbook_match'] = any(scenario['required_playbook'].lower() in pb.lower() for pb in playbook_names)
        
        if not result['playbook_match']:
            result['gaps'].append(f"No playbook for {scenario['required_playbook']}")
        else:
            result['strengths'].append(f"Relevant playbook exists: {scenario['required_playbook']}")
        
        # Estimate timeline reconstruction feasibility
        if result['log_availability'] >= 0.8 and result['playbook_match']:
            result['timeline_feasibility'] = 0.85
        elif result['log_availability'] >= 0.6:
            result['timeline_feasibility'] = 0.65
        else:
            result['timeline_feasibility'] = 0.40
        
        # Calculate overall readiness
        result['readiness_score'] = (
            result['log_availability'] * 0.4 +
            (1.0 if result['playbook_match'] else 0.0) * 0.3 +
            result['timeline_feasibility'] * 0.3
        )
        
        return result
    
    def _display_scenario_results(self):
        """Display scenario testing results"""
        print(f"{Color.BOLD}Scenario Testing Results:{Color.RESET}\n")
        
        for scenario in self.scenarios:
            print(f"{Color.BOLD}{scenario['name']}{Color.RESET}")
            print(f"  {Color.DIM}{scenario['description']}{Color.RESET}")
            print(f"  Readiness Score: {self._score_to_color(scenario['readiness_score'])}")
            print(f"  Log Availability: {self._score_to_color(scenario['log_availability'])}")
            print(f"  Timeline Feasibility: {self._score_to_color(scenario['timeline_feasibility'])}")
            
            if scenario['strengths']:
                print(f"  {Color.GREEN}Strengths:{Color.RESET}")
                for strength in scenario['strengths']:
                    print(f"    • {strength}")
            
            if scenario['gaps']:
                print(f"  {Color.RED}Gaps:{Color.RESET}")
                for gap in scenario['gaps']:
                    print(f"    • {gap}")
            print()
    
    def _score_to_color(self, score: float) -> str:
        """Convert score to colored display"""
        percentage = int(score * 100)
        if score >= 0.8:
            color = Color.GREEN
        elif score >= 0.65:
            color = Color.YELLOW
        else:
            color = Color.RED
        return f"{color}{percentage}%{Color.RESET}"


# ============================================================================
# MODULE: ASSESSMENT SUMMARY & RECOMMENDATIONS
# ============================================================================

class AssessmentModule:
    """Module for generating comprehensive readiness assessment"""
    
    def __init__(self, environment: EnvironmentModule, log_module: LogAnalysisModule,
                 playbook_module: PlaybookModule, policy_module: PolicyToolModule,
                 scenario_module: ScenarioModule):
        self.environment = environment
        self.log_module = log_module
        self.playbook_module = playbook_module
        self.policy_module = policy_module
        self.scenario_module = scenario_module
        self.assessment: Optional[ReadinessAssessment] = None
    
    def generate_assessment(self) -> ReadinessAssessment:
        """Generate comprehensive readiness assessment"""
        print_section_header("READINESS ASSESSMENT")
        
        print_info("Generating comprehensive incident response readiness assessment...")
        print()
        
        # Calculate component scores
        evidence_score = self.log_module.get_evidence_availability_score()
        playbook_score = self.playbook_module.get_playbook_effectiveness_score()
        policy_score = self.policy_module.get_policy_alignment_score()
        
        # Calculate timeline reconstruction capability
        timeline_score = self._calculate_timeline_score(evidence_score, policy_score)
        
        # Calculate overall score with weights
        overall_score = (
            evidence_score * 0.30 +
            playbook_score * 0.25 +
            policy_score * 0.25 +
            timeline_score * 0.20
        )
        
        # Determine readiness level
        readiness_level = self._determine_readiness_level(overall_score)
        
        # Collect all gaps and prioritize
        critical_gaps, high_gaps, medium_gaps = self._prioritize_gaps()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        self.assessment = ReadinessAssessment(
            overall_score=overall_score,
            readiness_level=readiness_level.value,
            evidence_availability=evidence_score,
            timeline_reconstruction=timeline_score,
            playbook_effectiveness=playbook_score,
            policy_alignment=policy_score,
            critical_gaps=critical_gaps,
            high_priority_gaps=high_gaps,
            medium_priority_gaps=medium_gaps,
            recommendations=recommendations
        )
        
        self._display_assessment()
        return self.assessment
    
    def _calculate_timeline_score(self, evidence_score: float, policy_score: float) -> float:
        """Calculate timeline reconstruction capability"""
        # Timeline reconstruction depends on evidence quality and tool integration
        base_score = evidence_score * 0.7 + policy_score * 0.3
        
        # Penalize if retention is insufficient
        if self.environment.profile and self.environment.profile.retention_days < 90:
            base_score *= 0.85
        
        return base_score
    
    def _determine_readiness_level(self, score: float) -> ReadinessLevel:
        """Determine overall readiness level"""
        if score >= 0.85:
            return ReadinessLevel.EXCELLENT
        elif score >= 0.75:
            return ReadinessLevel.HIGH
        elif score >= 0.60:
            return ReadinessLevel.MODERATE
        elif score >= 0.40:
            return ReadinessLevel.LOW
        else:
            return ReadinessLevel.CRITICAL
    
    def _prioritize_gaps(self) -> tuple:
        """Prioritize identified gaps"""
        critical_gaps = []
        high_gaps = []
        medium_gaps = []
        
        # Evidence gaps
        if self.log_module.get_evidence_availability_score() < 0.60:
            critical_gaps.append("Insufficient log coverage for effective incident investigation")
        
        for result in self.log_module.results:
            if not result.retention_compliance:
                high_gaps.append(f"{result.source_name}: Inadequate retention period")
        
        # Playbook gaps
        if self.playbook_module.get_playbook_effectiveness_score() < 0.60:
            critical_gaps.append("Incident response playbooks lack clarity or completeness")
        
        for result in self.playbook_module.results:
            if result.unrealistic_assumptions:
                high_gaps.append(f"{result.playbook_name}: Contains unrealistic assumptions")
        
        # Policy and tool gaps
        if self.policy_module.policy_score < 0.60:
            critical_gaps.append("Security policies inadequate for effective incident response")
        
        if self.policy_module.tool_score < 0.70:
            high_gaps.append("Security tools not fully integrated into response workflow")
        
        for bottleneck in self.policy_module.bottlenecks:
            medium_gaps.append(bottleneck)
        
        # Scenario-specific gaps
        if self.scenario_module.scenarios:
            avg_scenario_score = sum(s['readiness_score'] for s in self.scenario_module.scenarios) / len(self.scenario_module.scenarios)
            if avg_scenario_score < 0.65:
                high_gaps.append("Limited readiness for common incident scenarios")
        
        return critical_gaps, high_gaps, medium_gaps
    
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Evidence recommendations
        if self.log_module.get_evidence_availability_score() < 0.75:
            recommendations.append("Implement comprehensive logging across all critical systems")
            recommendations.append("Deploy centralized log management (SIEM) platform")
        
        if self.environment.profile and self.environment.profile.retention_days < 90:
            recommendations.append("Extend log retention to minimum 90 days (180 days recommended)")
        
        # Playbook recommendations
        if self.playbook_module.get_playbook_effectiveness_score() < 0.70:
            recommendations.append("Conduct comprehensive playbook review and update cycle")
            recommendations.append("Schedule quarterly tabletop exercises to validate procedures")
        
        # Policy recommendations
        if self.policy_module.policy_score < 0.70:
            recommendations.append("Formalize incident response policies and procedures")
            recommendations.append("Establish clear escalation paths and approval thresholds")
        
        # Tool recommendations
        if self.policy_module.tool_score < 0.75:
            recommendations.append("Integrate security tools into unified incident response platform")
            recommendations.append("Implement SOAR capabilities for automated response actions")
        
        # Timeline recommendations
        timeline_score = self.assessment.timeline_reconstruction if self.assessment else 0.0
        if timeline_score < 0.70:
            recommendations.append("Improve log correlation and timestamp synchronization")
            recommendations.append("Deploy network traffic analysis (NTA) for comprehensive visibility")
        
        # General recommendations
        recommendations.append("Establish 24/7 SOC coverage or engage MDR provider")
        recommendations.append("Conduct annual incident response capability assessment")
        recommendations.append("Develop incident response metrics and KPIs")
        
        return recommendations[:15]  # Limit to top 15
    
    def _display_assessment(self):
        """Display comprehensive assessment"""
        if not self.assessment:
            return
        
        # Overall readiness
        print(f"{Color.BOLD}OVERALL INCIDENT RESPONSE READINESS{Color.RESET}")
        print(f"{Color.BOLD}{'═'*60}{Color.RESET}\n")
        
        level_color = self._get_level_color(self.assessment.readiness_level)
        print(f"{Color.BOLD}Readiness Level:{Color.RESET} {level_color}{self.assessment.readiness_level}{Color.RESET}")
        print(f"{Color.BOLD}Overall Score:{Color.RESET} {self._score_to_color(self.assessment.overall_score)}\n")
        
        # Component scores
        print(f"{Color.BOLD}Component Scores:{Color.RESET}")
        print(f"  Evidence Availability:     {self._score_to_color(self.assessment.evidence_availability)}")
        print(f"  Timeline Reconstruction:   {self._score_to_color(self.assessment.timeline_reconstruction)}")
        print(f"  Playbook Effectiveness:    {self._score_to_color(self.assessment.playbook_effectiveness)}")
        print(f"  Policy Alignment:          {self._score_to_color(self.assessment.policy_alignment)}\n")
        
        # Critical gaps
        if self.assessment.critical_gaps:
            print(f"{Color.RED}{Color.BOLD}CRITICAL GAPS:{Color.RESET}")
            for gap in self.assessment.critical_gaps:
                print(f"  {Color.RED}⚠{Color.RESET} {gap}")
            print()
        
        # High priority gaps
        if self.assessment.high_priority_gaps:
            print(f"{Color.YELLOW}{Color.BOLD}HIGH PRIORITY GAPS:{Color.RESET}")
            for gap in self.assessment.high_priority_gaps[:5]:  # Limit display
                print(f"  {Color.YELLOW}•{Color.RESET} {gap}")
            print()
        
        # Top recommendations
        print(f"{Color.BOLD}TOP RECOMMENDATIONS:{Color.RESET}")
        for i, rec in enumerate(self.assessment.recommendations[:10], 1):
            print(f"  {Color.CYAN}{i}.{Color.RESET} {rec}")
        print()
    
    def _get_level_color(self, level: str) -> str:
        """Get color for readiness level"""
        colors = {
            'Excellent': Color.GREEN + Color.BOLD,
            'High': Color.GREEN,
            'Moderate': Color.YELLOW,
            'Low': Color.RED,
            'Critical': Color.RED + Color.BOLD
        }
        return colors.get(level, Color.WHITE)
    
    def _score_to_color(self, score: float) -> str:
        """Convert score to colored display"""
        percentage = int(score * 100)
        if score >= 0.85:
            color = Color.GREEN
        elif score >= 0.75:
            color = Color.YELLOW
        else:
            color = Color.RED
        return f"{color}{percentage}%{Color.RESET}"
    
    def export_assessment(self, format: str = 'json') -> str:
        """Export assessment to file"""
        if not self.assessment:
            print_error("No assessment available to export")
            return ""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == 'json':
            filename = f"irr_assessment_{timestamp}.json"
            data = asdict(self.assessment)
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            filename = f"irr_assessment_{timestamp}.yaml"
            data = asdict(self.assessment)
            with open(filename, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
        
        print_success(f"Assessment exported to: {filename}")
        return filename


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class IRRApplication:
    """Main IRR application orchestrator"""
    
    def __init__(self):
        self.environment = EnvironmentModule()
        self.log_analysis = LogAnalysisModule(self.environment)
        self.playbook = PlaybookModule()
        self.policy_tool = PolicyToolModule(self.environment)
        self.scenario = None
        self.assessment = None
    
    def display_consent_screen(self) -> bool:
        """Display consent and overview screen"""
        clear_screen()
        print_banner()
        
        print(f"{Color.BOLD}OVERVIEW & SCOPE{Color.RESET}")
        print(f"{Color.DIM}{'─'*60}{Color.RESET}\n")
        
        overview_text = """IRR (Incident Readiness & Response Evaluator) is a professional
assessment platform designed to evaluate your organization's capability
to respond effectively to security incidents.

This tool analyzes:
  • Log availability and evidence quality
  • Incident response playbook effectiveness
  • Security policy and tool readiness
  • Timeline reconstruction capability
  • Scenario-based response readiness

IRR is strictly analytical and does NOT:
  ✗ Simulate attacks or generate malicious activity
  ✗ Modify system configurations or data
  ✗ Access systems without explicit user input
  ✗ Store or transmit sensitive organizational data

All assessments are performed locally and remain confidential.
Results can be exported for internal review and improvement planning."""
        
        print(overview_text)
        print(f"\n{Color.DIM}{'─'*60}{Color.RESET}\n")
        
        consent = get_yes_no("Do you consent to proceed with the assessment")
        
        if not consent:
            print_info("Assessment cancelled. Exiting...")
            return False
        
        return True
    
    def display_main_menu(self) -> int:
        """Display main application menu"""
        clear_screen()
        print_banner()
        
        options = [
            "Full Assessment (All Modules)",
            "Environment Overview",
            "Log Analysis",
            "Playbook Evaluation",
            "Policy & Tool Readiness",
            "Scenario Testing",
            "Generate Assessment Report",
            "Export Results"
        ]
        
        return display_menu("MAIN MENU", options)
    
    def run_full_assessment(self):
        """Run complete assessment workflow"""
        print_section_header("FULL INCIDENT READINESS ASSESSMENT")
        print_info("Beginning comprehensive evaluation...\n")
        
        # Step 1: Environment
        if not self.environment.profile:
            self.environment.collect_environment_data()
            input(f"\n{Color.DIM}Press Enter to continue...{Color.RESET}")
        
        # Step 2: Log Analysis
        self.log_analysis.analyze_logs()
        input(f"\n{Color.DIM}Press Enter to continue...{Color.RESET}")
        
        # Step 3: Playbook Evaluation
        self.playbook.evaluate_playbooks()
        input(f"\n{Color.DIM}Press Enter to continue...{Color.RESET}")
        
        # Step 4: Policy & Tools
        self.policy_tool.evaluate_readiness()
        input(f"\n{Color.DIM}Press Enter to continue...{Color.RESET}")
        
        # Step 5: Scenarios (optional)
        self.scenario = ScenarioModule(self.environment, self.log_analysis, 
                                      self.playbook, self.policy_tool)
        self.scenario.run_scenario_testing()
        input(f"\n{Color.DIM}Press Enter to continue...{Color.RESET}")
        
        # Step 6: Generate Assessment
        self.assessment = AssessmentModule(self.environment, self.log_analysis,
                                          self.playbook, self.policy_tool, self.scenario)
        self.assessment.generate_assessment()
        
        input(f"\n{Color.DIM}Press Enter to return to main menu...{Color.RESET}")
    
    def run_individual_module(self, choice: int):
        """Run individual assessment module"""
        if choice == 2:  # Environment Overview
            if self.environment.profile:
                self.environment.display_environment_summary()
            else:
                self.environment.collect_environment_data()
        
        elif choice == 3:  # Log Analysis
            if not self.environment.profile:
                print_warning("Environment profile required first")
                if get_yes_no("Collect environment data now"):
                    self.environment.collect_environment_data()
                else:
                    return
            self.log_analysis.analyze_logs()
        
        elif choice == 4:  # Playbook Evaluation
            self.playbook.evaluate_playbooks()
        
        elif choice == 5:  # Policy & Tool Readiness
            if not self.environment.profile:
                print_warning("Environment profile required first")
                if get_yes_no("Collect environment data now"):
                    self.environment.collect_environment_data()
                else:
                    return
            self.policy_tool.evaluate_readiness()
        
        elif choice == 6:  # Scenario Testing
            if not self.log_analysis.results or not self.playbook.results:
                print_warning("Log analysis and playbook evaluation required first")
                return
            
            if not self.scenario:
                self.scenario = ScenarioModule(self.environment, self.log_analysis,
                                              self.playbook, self.policy_tool)
            self.scenario.run_scenario_testing()
        
        elif choice == 7:  # Generate Assessment
            if not self.log_analysis.results or not self.playbook.results:
                print_warning("Complete at least log analysis and playbook evaluation first")
                return
            
            if not self.scenario:
                self.scenario = ScenarioModule(self.environment, self.log_analysis,
                                              self.playbook, self.policy_tool)
            
            self.assessment = AssessmentModule(self.environment, self.log_analysis,
                                              self.playbook, self.policy_tool, self.scenario)
            self.assessment.generate_assessment()
        
        elif choice == 8:  # Export Results
            if not self.assessment or not self.assessment.assessment:
                print_warning("No assessment available to export")
                return
            
            format_choice = display_menu("Export Format", ["JSON", "YAML"])
            if format_choice == 0:
                return
            
            format_type = "json" if format_choice == 1 else "yaml"
            self.assessment.export_assessment(format_type)
        
        input(f"\n{Color.DIM}Press Enter to return to main menu...{Color.RESET}")
    
    def run(self):
        """Main application loop"""
        if not self.display_consent_screen():
            return
        
        while True:
            choice = self.display_main_menu()
            
            if choice == 0:
                clear_screen()
                print_banner()
                print(f"{Color.CYAN}Thank you for using IRR.{Color.RESET}")
                print(f"{Color.DIM}Assessment complete. Stay secure.{Color.RESET}\n")
                break
            
            elif choice == 1:
                self.run_full_assessment()
            
            else:
                self.run_individual_module(choice)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Application entry point"""
    try:
        app = IRRApplication()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}Assessment interrupted by user.{Color.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}Unexpected error: {e}{Color.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
