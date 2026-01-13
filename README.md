# IRR - Incident Readiness & Response Evaluator

> A professional cybersecurity assessment platform for evaluating incident response readiness

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)]()

---

## Overview

**IRR (Incident Readiness & Response Evaluator)** is a modular, terminal-friendly assessment platform designed to answer a critical question:

> **"Given the current environment, could this organization respond effectively to a real security incident?"**

Built for SOC teams, incident responders, and security architects, IRR provides comprehensive evaluation of incident response capabilities through systematic analysis of logs, playbooks, policies, and organizational readiness.

### Key Philosophy

IRR is **strictly analytical** and defensive in nature:
- ✅ Evaluates incident response readiness
- ✅ Identifies gaps in evidence and procedures
- ✅ Provides actionable recommendations
- ❌ Does NOT simulate attacks or generate malicious activity
- ❌ Does NOT modify systems or data
- ❌ Does NOT transmit organizational data

---

## Features

### Core Capabilities

**Evidence Analysis**
- Log availability and retention assessment
- Timestamp consistency validation
- Evidence quality scoring
- Gap identification for critical log sources

**Playbook Evaluation**
- Clarity and feasibility analysis
- Completeness assessment
- Ambiguity detection
- Unrealistic assumption identification

**Policy & Tool Readiness**
- Security policy maturity evaluation
- Tool integration assessment
- Decision bottleneck identification
- Response workflow analysis

**Scenario Testing**
- Hypothesis-driven readiness evaluation
- Common incident scenario assessment
- Timeline reconstruction capability testing
- Custom scenario support

**Comprehensive Reporting**
- Overall readiness scoring
- Prioritized gap analysis
- Actionable recommendations
- Exportable results (JSON/YAML)

### Design Principles

- **Modular Architecture**: Each component operates independently
- **Cross-Platform**: Compatible with Linux, macOS, Windows (PowerShell/WSL), Termux, VSCode terminal
- **CLI-First**: Professional terminal interface with intuitive navigation
- **Efficient**: Optimized for large-scale enterprise environments
- **Maintainable**: Clean, extensible codebase

---

## Installation

### Prerequisites

- Python 3.7 or higher
- Terminal access (any platform)
- PyYAML library (for YAML export functionality)

### Quick Setup

```bash
# Download IRR
wget https://example.com/irr.py
# or
curl -O https://example.com/irr.py

# Install dependencies
pip install pyyaml

# Make executable (Linux/macOS)
chmod +x irr.py

# Run IRR
python3 irr.py
# or
./irr.py
```

### Platform-Specific Notes

**Linux/macOS**
```bash
python3 irr.py
```

**Windows (PowerShell)**
```powershell
python irr.py
```

**Windows (WSL)**
```bash
python3 irr.py
```

**Termux (Android)**
```bash
pkg install python
pip install pyyaml
python irr.py
```

---

## Usage

### Quick Start

1. **Launch IRR**
   ```bash
   python3 irr.py
   ```

2. **Review and Accept Consent Screen**
   - Understand tool scope and limitations
   - Confirm consent to proceed

3. **Choose Assessment Mode**
   - **Full Assessment**: Complete evaluation (recommended for first use)
   - **Individual Modules**: Targeted analysis of specific areas

4. **Follow Interactive Prompts**
   - Provide organizational metadata
   - Answer readiness questions
   - Review analysis results

5. **Generate Report**
   - Review comprehensive readiness assessment
   - Export results for stakeholder review

### Assessment Workflow

```
┌─────────────────────────────────────┐
│  1. Environment Overview            │
│     └─ Collect organizational data  │
├─────────────────────────────────────┤
│  2. Log Analysis                    │
│     └─ Evaluate evidence quality    │
├─────────────────────────────────────┤
│  3. Playbook Evaluation             │
│     └─ Assess response procedures   │
├─────────────────────────────────────┤
│  4. Policy & Tool Readiness         │
│     └─ Check policy maturity        │
├─────────────────────────────────────┤
│  5. Scenario Testing (Optional)     │
│     └─ Test real-world scenarios    │
├─────────────────────────────────────┤
│  6. Assessment Summary              │
│     └─ Generate comprehensive report│
└─────────────────────────────────────┘
```

---

## Module Descriptions

### 1. Environment Overview

**Purpose**: Establish baseline understanding of organizational security posture

**Collects**:
- Platform coverage (Windows, Linux, macOS, Cloud)
- Endpoint inventory
- Network architecture
- Security tool stack
- Log source availability
- Retention policies

**Output**: Structured environment profile for contextualized analysis

---

### 2. Log Analysis

**Purpose**: Evaluate evidence availability and quality for incident investigation

**Analyzes**:
- Log source availability
- Retention period compliance
- Timestamp consistency
- Log volume adequacy
- Evidence completeness

**Scoring Criteria**:
- **Availability**: Is the log source present and accessible?
- **Retention Compliance**: Does retention meet industry standards (90+ days)?
- **Timestamp Consistency**: Are timestamps synchronized and reliable?
- **Volume**: Is logging granular enough for investigation?
- **Completeness**: Are critical security events captured?

**Output**: Per-source analysis with issues and recommendations

**Example Issues Detected**:
- Insufficient retention periods
- Missing critical log sources
- Timestamp synchronization problems
- Incomplete security event coverage

---

### 3. Playbook Evaluation

**Purpose**: Assess incident response playbook effectiveness and usability

**Evaluates**:
- **Clarity**: Are procedures unambiguous and actionable?
- **Feasibility**: Can steps be realistically executed with available tools?
- **Completeness**: Are all critical response phases covered?
- **Assumptions**: Are there unrealistic dependencies?

**Standard Playbooks Assessed**:
- Malware Infection Response
- Phishing Incident Response
- Data Breach Response
- Ransomware Response
- Insider Threat Response
- DDoS Attack Response

**Output**: Effectiveness scores, identified ambiguities, missing elements

**Common Gaps Identified**:
- Ambiguous containment procedures
- Missing escalation criteria
- Undefined communication protocols
- Lack of evidence preservation guidance

---

### 4. Policy & Tool Readiness

**Purpose**: Evaluate organizational preparedness and identify bottlenecks

**Assesses**:
- Incident response policy maturity
- Escalation procedures
- Communication protocols
- Tool integration effectiveness
- Decision-making bottlenecks

**Bottleneck Categories**:
- Manual processes requiring automation
- Approval delays for critical actions
- Tool fragmentation and integration gaps
- Expertise or coverage limitations
- Communication coordination overhead

**Output**: Policy/tool scores, bottleneck analysis, integration recommendations

---

### 5. Scenario Testing

**Purpose**: Validate response capability against realistic incident scenarios

**Methodology**:
- Select predefined or custom scenarios
- Evaluate log availability for scenario
- Verify playbook applicability
- Assess timeline reconstruction feasibility
- Identify scenario-specific gaps

**Predefined Scenarios**:
- **Ransomware Attack**: Multiple endpoints encrypted, ransom note detected
- **Credential Compromise**: Suspicious authentication from unusual location
- **Data Exfiltration**: Large outbound data transfer to unknown destination

**Output**: Scenario-specific readiness scores, strengths, and gaps

---

### 6. Assessment Summary

**Purpose**: Provide comprehensive readiness evaluation with prioritized recommendations

**Generates**:
- Overall readiness score (0-100%)
- Readiness level classification
- Component score breakdown
- Prioritized gap analysis (Critical/High/Medium)
- Top 10-15 actionable recommendations

**Readiness Levels**:
- **Excellent** (85%+): Mature incident response capability
- **High** (75-84%): Strong readiness with minor gaps
- **Moderate** (60-74%): Adequate baseline, improvement needed
- **Low** (40-59%): Significant gaps requiring attention
- **Critical** (<40%): Fundamental readiness issues

**Scoring Weights**:
- Evidence Availability: 30%
- Playbook Effectiveness: 25%
- Policy Alignment: 25%
- Timeline Reconstruction: 20%

---

## Output Examples

### Console Output

```
════════════════════════════════════════════════════════════
           OVERALL INCIDENT RESPONSE READINESS
════════════════════════════════════════════════════════════

Readiness Level: High
Overall Score: 78%

Component Scores:
  Evidence Availability:     82%
  Timeline Reconstruction:   75%
  Playbook Effectiveness:    73%
  Policy Alignment:          80%

CRITICAL GAPS:
  ⚠ Incident response playbooks lack clarity or completeness

HIGH PRIORITY GAPS:
  • Windows Event Logs: Inadequate retention period
  • Ransomware Response: Contains unrealistic assumptions
  • Security tools not fully integrated into response workflow
  • Limited readiness for common incident scenarios

TOP RECOMMENDATIONS:
  1. Extend log retention to minimum 90 days (180 days recommended)
  2. Conduct comprehensive playbook review and update cycle
  3. Integrate security tools into unified incident response platform
  4. Schedule quarterly tabletop exercises to validate procedures
  5. Implement SOAR capabilities for automated response actions
```

### Exported Report (JSON)

```json
{
  "overall_score": 0.78,
  "readiness_level": "High",
  "evidence_availability": 0.82,
  "timeline_reconstruction": 0.75,
  "playbook_effectiveness": 0.73,
  "policy_alignment": 0.80,
  "critical_gaps": [
    "Incident response playbooks lack clarity or completeness"
  ],
  "high_priority_gaps": [
    "Windows Event Logs: Inadequate retention period",
    "Ransomware Response: Contains unrealistic assumptions",
    "Security tools not fully integrated into response workflow"
  ],
  "recommendations": [
    "Extend log retention to minimum 90 days (180 days recommended)",
    "Conduct comprehensive playbook review and update cycle",
    "Integrate security tools into unified incident response platform"
  ],
  "timestamp": "2026-01-13T14:30:45.123456"
}
```

---

## Best Practices

### Preparation

**Before Assessment**
1. Gather inventory of security tools and log sources
2. Collect current incident response playbooks
3. Review existing security policies
4. Identify key stakeholders for follow-up actions

**Optimal Assessment Frequency**
- Initial assessment: Comprehensive full evaluation
- Quarterly: Targeted re-assessment of identified gaps
- Annual: Complete reassessment
- Post-incident: Validation of lessons learned implementation

### During Assessment

**Accuracy Tips**
- Be honest in responses—inflated answers reduce value
- Involve multiple team members for comprehensive perspective
- Document any uncertainties for follow-up investigation
- Take time to review playbooks and policies accurately

**Module Sequencing**
- **First-time users**: Run full assessment in order
- **Follow-up assessments**: Focus on previously identified gaps
- **Targeted reviews**: Individual modules as needed

### After Assessment

**Action Planning**
1. Review results with incident response team
2. Prioritize recommendations based on:
   - Critical gaps requiring immediate attention
   - High-value, low-effort improvements
   - Long-term strategic enhancements
3. Assign ownership for each recommendation
4. Set realistic timelines for remediation
5. Schedule follow-up assessment

**Stakeholder Communication**
- Executive summary: Focus on readiness level and critical gaps
- Technical teams: Detailed findings and specific recommendations
- Management: Resource requirements and timeline estimates

---

## Methodology

### Assessment Framework

IRR employs a structured methodology based on industry best practices:

**1. Evidence-Based Analysis**
- Evaluates actual log availability, not theoretical capability
- Assesses retention against compliance and investigative needs
- Validates timestamp reliability for timeline reconstruction

**2. Procedural Effectiveness**
- Tests playbook clarity through structured evaluation
- Identifies dependencies and single points of failure
- Validates feasibility with available tools and expertise

**3. Organizational Readiness**
- Assesses policy maturity and documentation
- Identifies process bottlenecks and approval delays
- Evaluates tool integration and automation

**4. Scenario Validation**
- Tests readiness against realistic incident types
- Validates end-to-end response capability
- Identifies scenario-specific gaps

### Scoring Methodology

**Component Scoring**
- Each module generates 0-100% scores
- Scores combine multiple sub-factors
- Weighting reflects relative importance to incident response

**Overall Score Calculation**
```
Overall Score = (Evidence × 0.30) + 
                (Playbooks × 0.25) + 
                (Policy × 0.25) + 
                (Timeline × 0.20)
```

**Gap Prioritization**
- **Critical**: Fundamental capabilities absent, high impact on response
- **High Priority**: Significant weaknesses with material impact
- **Medium Priority**: Process improvements and optimization opportunities

---

## Frequently Asked Questions

### General Questions

**Q: Is IRR a penetration testing or attack simulation tool?**
A: No. IRR is strictly an analytical assessment platform. It does not simulate attacks, generate malicious activity, or modify systems in any way.

**Q: What data does IRR collect or transmit?**
A: IRR processes all data locally on your system. No organizational data is transmitted externally. Exported reports are saved locally for your review.

**Q: How long does an assessment take?**
A: A full assessment typically takes 30-60 minutes, depending on organizational complexity and the depth of scenario testing performed.

**Q: Do I need special permissions to run IRR?**
A: No special system permissions are required. IRR operates as a standard user application and relies entirely on user-provided inputs.

### Technical Questions

**Q: What platforms are supported?**
A: IRR is compatible with Linux, macOS, Windows (PowerShell/WSL), Termux (Android), and any environment with Python 3.7+.

**Q: Can IRR analyze actual log files?**
A: The current version focuses on organizational capability assessment rather than direct log analysis. It evaluates whether adequate logs exist, not their specific contents.

**Q: Can I integrate IRR into automated workflows?**
A: Yes. IRR can be used in scripted assessments, and the JSON/YAML export feature supports integration with reporting or ticketing systems.

**Q: How accurate are the scores?**
A: Scores are based on established incident response best practices and industry standards. Accuracy depends on the honesty and thoroughness of user inputs.

### Assessment Questions

**Q: Should I run individual modules or full assessment?**
A: For initial evaluation, run the full assessment. For targeted follow-ups or specific concerns, individual modules are appropriate.

**Q: How often should we run assessments?**
A: Recommended frequency: Full assessment annually, targeted reassessments quarterly, and post-incident validation after major incidents.

**Q: What if we don't have formal playbooks?**
A: This is precisely the type of gap IRR identifies. The playbook module will help you understand what's missing and provide recommendations for development.

**Q: Can multiple people contribute to one assessment?**
A: Yes. You can pause at any time and gather input from subject matter experts before continuing. Consider involving SOC, IT, legal, and management stakeholders.

---

## Troubleshooting

### Common Issues

**Issue: Colors not displaying correctly**
- **Cause**: Terminal doesn't support ANSI color codes
- **Solution**: Use a modern terminal emulator, or colors will degrade gracefully to plain text

**Issue: "ModuleNotFoundError: No module named 'yaml'"**
- **Cause**: PyYAML not installed
- **Solution**: Run `pip install pyyaml`

**Issue: Assessment seems inaccurate**
- **Cause**: Insufficient or inaccurate input data
- **Solution**: Review responses carefully, involve multiple team members, verify actual capabilities

**Issue: Can't export results**
- **Cause**: Write permissions or path issues
- **Solution**: Ensure you have write permissions in the current directory

### Getting Help

For issues, questions, or feedback:
1. Review this documentation thoroughly
2. Check that all prerequisites are installed
3. Verify Python version meets requirements (3.7+)
4. Ensure proper file permissions

---

## Professional Use Cases

### Security Operations Centers (SOCs)

**Capability Validation**
- Assess readiness to handle incident volumes
- Validate log coverage for common attack vectors
- Identify automation opportunities

**Team Training**
- Use scenario testing for training exercises
- Identify knowledge gaps and training needs
- Validate playbook effectiveness

### Incident Response Teams

**Preparedness Assessment**
- Evaluate response procedures before incidents occur
- Identify single points of failure
- Test timeline reconstruction capability

**Post-Incident Reviews**
- Validate that identified improvements have been implemented
- Measure progress over time
- Demonstrate enhanced readiness to stakeholders

### Security Architects

**Architecture Decisions**
- Justify security tool investments
- Demonstrate value of log retention extensions
- Support business cases for SIEM/SOAR platforms

**Compliance and Governance**
- Document incident response capabilities
- Support audit and compliance activities
- Demonstrate continuous improvement

### Management and Leadership

**Risk Communication**
- Translate technical readiness into business risk
- Prioritize security investments
- Track improvement initiatives

**Resource Planning**
- Identify staffing gaps (24/7 coverage, expertise)
- Justify budget for tools and training
- Plan strategic improvements

---

## Roadmap and Future Enhancements

**Planned Features** (Future Versions)
- Direct log file analysis capabilities
- Integration with SIEM platforms via APIs
- Historical trend analysis and maturity tracking
- Automated playbook testing framework
- Multi-organization comparative benchmarking
- Compliance framework mapping (NIST, ISO, etc.)

---

## Contributing

IRR is designed to be extensible. Contributions are welcome in the following areas:

- Additional scenario templates
- Enhanced scoring algorithms
- New analysis modules
- Platform-specific optimizations
- Documentation improvements
- Translation to other languages

---

## License

IRR is released under the MIT License. See LICENSE file for details.

---

## Conclusion

IRR provides security teams with a systematic, repeatable method to evaluate and improve incident response readiness. By identifying gaps before incidents occur, organizations can respond more effectively when real threats emerge.

**Remember**: The goal isn't a perfect score—it's continuous improvement and realistic understanding of capabilities.

---

**IRR - Know Your Readiness Before You Need It**

*Built for defenders, by defenders.*
