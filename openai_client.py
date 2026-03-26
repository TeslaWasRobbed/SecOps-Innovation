"""
OpenAI Azure Client for SecOps Innovation Project
Provides a configured client for interacting with Azure OpenAI services.
Integrates with VirusTotal, GitHub, and other security APIs for comprehensive analysis.
"""

import os
from openai import AzureOpenAI
from typing import List, Dict, Any, Optional

class SecOpsAIClient:
    """Azure OpenAI client configured for SecOps operations."""
    
    def __init__(self):
        # Azure OpenAI Configuration
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "<your-endpoint>")
        self.subscription_key = os.getenv("AZURE_OPENAI_KEY", "<your-api-key>")
        self.api_version = "2024-12-01-preview"
        self.model_name = "gpt-5"
        self.deployment = "gpt-5"
        
        # Other API configurations for SecOps integrations
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_repo = os.getenv("GITHUB_REPO")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        
        # Initialize the OpenAI client
        self.client = AzureOpenAI(
            api_version=self.api_version,
            azure_endpoint=self.endpoint,
            api_key=self.subscription_key,
        )
    
    def chat_completion(
        self, 
        messages: List[Dict[str, str]], 
        max_tokens: int = 16384,
        temperature: float = 0.7
    ) -> str:
        """
        Send a chat completion request to Azure OpenAI.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            max_tokens: Maximum tokens for completion
            temperature: Sampling temperature (0.0 to 1.0)
            
        Returns:
            The assistant's response content
        """
        try:
            response = self.client.chat.completions.create(
                messages=messages,
                max_completion_tokens=max_tokens,
                model=self.deployment,
                temperature=temperature
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error calling Azure OpenAI: {e}")
            return None
    
    def analyze_threat_intelligence(self, threat_data: str) -> str:
        """
        Analyze threat intelligence data using AI.
        
        Args:
            threat_data: Raw threat intelligence text
            
        Returns:
            AI analysis of the threat data
        """
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity analyst specializing in threat intelligence. Analyze the provided data and provide insights on threats, vulnerabilities, and recommended actions."
            },
            {
                "role": "user",
                "content": f"Please analyze this threat intelligence data:\n\n{threat_data}"
            }
        ]
        
        return self.chat_completion(messages, temperature=0.3)
    
    def generate_security_summary(self, raw_data: str, audience: str = "executive") -> str:
        """
        Generate a security summary tailored for specific audiences.
        
        Args:
            raw_data: Raw security data to summarize
            audience: Target audience ('executive', 'technical', 'stakeholder')
            
        Returns:
            Formatted summary appropriate for the audience
        """
        audience_prompts = {
            "executive": "Create an executive summary focusing on business impact, risk levels, and high-level recommendations.",
            "technical": "Provide a technical analysis with detailed remediation steps, IOCs, and implementation guidance.",
            "stakeholder": "Generate a stakeholder brief with clear priorities, timelines, and actionable items."
        }
        
        prompt = audience_prompts.get(audience, audience_prompts["stakeholder"])
        
        messages = [
            {
                "role": "system",
                "content": f"You are a cybersecurity communication specialist. {prompt}"
            },
            {
                "role": "user",
                "content": f"Summarize this security data:\n\n{raw_data}"
            }
        ]
        
        return self.chat_completion(messages, temperature=0.4)
    
    def analyze_with_virustotal_context(self, ioc_data: str, vt_results: Dict = None) -> str:
        """
        Analyze IOCs with VirusTotal context using AI.
        
        Args:
            ioc_data: Indicators of Compromise data
            vt_results: Optional VirusTotal API results for enrichment
            
        Returns:
            AI analysis combining IOC data with VirusTotal intelligence
        """
        context = f"IOC Data:\n{ioc_data}"
        
        if vt_results and self.virustotal_key:
            context += f"\n\nVirusTotal Results:\n{vt_results}"
        elif not self.virustotal_key:
            context += "\n\nNote: VirusTotal API key not configured - analysis based on IOC data only."
        
        messages = [
            {
                "role": "system",
                "content": "You are a malware analyst. Analyze the provided IOCs and VirusTotal data to assess threat severity, attribution, and recommended defensive actions."
            },
            {
                "role": "user",
                "content": context
            }
        ]
        
        return self.chat_completion(messages, temperature=0.2)
    
    def generate_github_security_advisory(self, vulnerability_data: str) -> str:
        """
        Generate GitHub security advisory content from vulnerability data.
        
        Args:
            vulnerability_data: Raw vulnerability information
            
        Returns:
            Formatted security advisory suitable for GitHub
        """
        repo_context = f" for repository {self.github_repo}" if self.github_repo else ""
        
        messages = [
            {
                "role": "system",
                "content": f"You are a security researcher creating GitHub security advisories. Generate a well-structured advisory{repo_context} following GitHub's security advisory format."
            },
            {
                "role": "user",
                "content": f"Create a security advisory from this vulnerability data:\n\n{vulnerability_data}"
            }
        ]
        
        return self.chat_completion(messages, temperature=0.3)
    
    def check_api_availability(self) -> Dict[str, bool]:
        """
        Check which APIs are properly configured.
        
        Returns:
            Dictionary showing availability of each API integration
        """
        return {
            "azure_openai": bool(self.endpoint and self.subscription_key and 
                                self.endpoint != "<your-endpoint>" and 
                                self.subscription_key != "<your-api-key>"),
            "virustotal": bool(self.virustotal_key),
            "github": bool(self.github_token and self.github_repo),
            "anthropic": bool(self.anthropic_key)
        }


def main():
    """Example usage of the SecOps AI Client."""
    
    # Initialize the client
    ai_client = SecOpsAIClient()
    
    # Check API availability
    print("API Availability Check:")
    api_status = ai_client.check_api_availability()
    for api, available in api_status.items():
        status = "✓ Available" if available else "✗ Not configured"
        print(f"  {api.replace('_', ' ').title()}: {status}")
    
    print("\n" + "="*50)
    
    # Example: Original conversation from your code
    print("\nExample 1: Basic Chat Completion")
    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant.",
        },
        {
            "role": "user",
            "content": "I am going to Paris, what should I see?",
        },
        {
            "role": "assistant",
            "content": "Paris, the capital of France, is known for its stunning architecture, art museums, historical landmarks, and romantic atmosphere. Here are some of the top attractions to see in Paris:\n\n1. The Eiffel Tower: The iconic Eiffel Tower is one of the most recognizable landmarks in the world and offers breathtaking views of the city.\n2. The Louvre Museum: The Louvre is one of the worlds largest and most famous museums, housing an impressive collection of art and artifacts, including the Mona Lisa.\n3. Notre-Dame Cathedral: This beautiful cathedral is one of the most famous landmarks in Paris and is known for its Gothic architecture and stunning stained glass windows.\n\nThese are just a few of the many attractions that Paris has to offer. With so much to see and do, its no wonder that Paris is one of the most popular tourist destinations in the world.",
        },
        {
            "role": "user",
            "content": "What is so great about #1?",
        }
    ]
    
    if api_status["azure_openai"]:
        response = ai_client.chat_completion(messages)
        if response:
            print("AI Response:")
            print(response)
        else:
            print("Failed to get response from AI")
    else:
        print("Azure OpenAI not configured - skipping example")
    
    # Example: Threat Intelligence Analysis
    print("\n" + "="*50)
    print("\nExample 2: Threat Intelligence Analysis")
    
    sample_threat_data = """
    IOC: 192.168.1.100
    Malware Family: Emotet
    First Seen: 2026-03-25
    Campaign: Banking Trojan Distribution
    """
    
    if api_status["azure_openai"]:
        analysis = ai_client.analyze_threat_intelligence(sample_threat_data)
        if analysis:
            print("Threat Analysis:")
            print(analysis[:200] + "..." if len(analysis) > 200 else analysis)
    else:
        print("Azure OpenAI not configured - skipping threat analysis example")


if __name__ == "__main__":
    main()