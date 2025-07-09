#!/usr/bin/env python3

"""
VaultScope Enterprise - Cross-Platform Test Suite
This script performs comprehensive testing across different platforms and environments.
"""

import os
import sys
import subprocess
import platform
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class TestResult:
    """Represents the result of a test execution"""
    def __init__(self, name: str, passed: bool, message: str = "", duration: float = 0.0):
        self.name = name
        self.passed = passed
        self.message = message
        self.duration = duration
        self.timestamp = datetime.now()

class CrossPlatformTester:
    """Main test orchestrator for cross-platform testing"""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.start_time = time.time()
        self.platform_info = self._get_platform_info()
        self.java_version = self._get_java_version()
        self.maven_version = self._get_maven_version()
        
    def _get_platform_info(self) -> Dict[str, str]:
        """Get detailed platform information"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'architecture': platform.architecture()[0]
        }
    
    def _get_java_version(self) -> Optional[str]:
        """Get Java version"""
        try:
            result = subprocess.run(['java', '-version'], 
                                  capture_output=True, text=True)
            return result.stderr.split('\n')[0] if result.stderr else None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None
    
    def _get_maven_version(self) -> Optional[str]:
        """Get Maven version"""
        try:
            result = subprocess.run(['mvn', '-version'], 
                                  capture_output=True, text=True)
            return result.stdout.split('\n')[0] if result.stdout else None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None
    
    def _run_command(self, command: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a command with timeout and error handling"""
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out after {timeout} seconds")
        except FileNotFoundError:
            raise Exception(f"Command not found: {command[0]}")
    
    def _print_status(self, message: str, color: str = Colors.BLUE):
        """Print status message with color"""
        print(f"{color}[INFO]{Colors.END} {message}")
    
    def _print_success(self, message: str):
        """Print success message"""
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    def _print_warning(self, message: str):
        """Print warning message"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    def _print_error(self, message: str):
        """Print error message"""
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    def add_result(self, result: TestResult):
        """Add a test result to the collection"""
        self.results.append(result)
        if result.passed:
            self._print_success(f"{result.name}: {result.message}")
        else:
            self._print_error(f"{result.name}: {result.message}")
    
    def test_environment_setup(self) -> bool:
        """Test environment setup and prerequisites"""
        self._print_status("Testing environment setup...")
        
        # Test Java installation
        start_time = time.time()
        try:
            if self.java_version:
                # Check Java version (should be 17+)
                version_parts = self.java_version.split('"')[1].split('.')
                major_version = int(version_parts[0])
                
                if major_version >= 17:
                    self.add_result(TestResult(
                        "Java Version Check",
                        True,
                        f"Java {major_version} detected",
                        time.time() - start_time
                    ))
                else:
                    self.add_result(TestResult(
                        "Java Version Check",
                        False,
                        f"Java {major_version} is too old (17+ required)",
                        time.time() - start_time
                    ))
                    return False
            else:
                self.add_result(TestResult(
                    "Java Version Check",
                    False,
                    "Java not found",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Java Version Check",
                False,
                f"Error checking Java: {str(e)}",
                time.time() - start_time
            ))
            return False
        
        # Test Maven installation
        start_time = time.time()
        try:
            if self.maven_version:
                self.add_result(TestResult(
                    "Maven Installation Check",
                    True,
                    f"Maven found: {self.maven_version.split()[2]}",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "Maven Installation Check",
                    False,
                    "Maven not found",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Maven Installation Check",
                False,
                f"Error checking Maven: {str(e)}",
                time.time() - start_time
            ))
            return False
        
        return True
    
    def test_build_process(self) -> bool:
        """Test the build process"""
        self._print_status("Testing build process...")
        
        # Test Maven compile
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'clean', 'compile', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "Maven Compile",
                    True,
                    "Compilation successful",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "Maven Compile",
                    False,
                    f"Compilation failed: {result.stderr}",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Maven Compile",
                False,
                f"Error during compilation: {str(e)}",
                time.time() - start_time
            ))
            return False
        
        # Test Maven package
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'package', '-DskipTests', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "Maven Package",
                    True,
                    "Packaging successful",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "Maven Package",
                    False,
                    f"Packaging failed: {result.stderr}",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Maven Package",
                False,
                f"Error during packaging: {str(e)}",
                time.time() - start_time
            ))
            return False
        
        return True
    
    def test_unit_tests(self) -> bool:
        """Test unit tests execution"""
        self._print_status("Running unit tests...")
        
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'test', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "Unit Tests",
                    True,
                    "All unit tests passed",
                    time.time() - start_time
                ))
                return True
            else:
                self.add_result(TestResult(
                    "Unit Tests",
                    False,
                    f"Unit tests failed: {result.stderr}",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Unit Tests",
                False,
                f"Error running unit tests: {str(e)}",
                time.time() - start_time
            ))
            return False
    
    def test_integration_tests(self) -> bool:
        """Test integration tests execution"""
        self._print_status("Running integration tests...")
        
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'verify', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "Integration Tests",
                    True,
                    "All integration tests passed",
                    time.time() - start_time
                ))
                return True
            else:
                self.add_result(TestResult(
                    "Integration Tests",
                    False,
                    f"Integration tests failed: {result.stderr}",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Integration Tests",
                False,
                f"Error running integration tests: {str(e)}",
                time.time() - start_time
            ))
            return False
    
    def test_security_checks(self) -> bool:
        """Test security checks and analysis"""
        self._print_status("Running security checks...")
        
        # OWASP Dependency Check
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'org.owasp:dependency-check-maven:check', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "OWASP Dependency Check",
                    True,
                    "No critical vulnerabilities found",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "OWASP Dependency Check",
                    False,
                    f"Dependency vulnerabilities found: {result.stderr}",
                    time.time() - start_time
                ))
        except Exception as e:
            self.add_result(TestResult(
                "OWASP Dependency Check",
                False,
                f"Error running dependency check: {str(e)}",
                time.time() - start_time
            ))
        
        # SpotBugs Analysis
        start_time = time.time()
        try:
            result = self._run_command(['mvn', 'spotbugs:check', '-q'])
            if result.returncode == 0:
                self.add_result(TestResult(
                    "SpotBugs Analysis",
                    True,
                    "No critical code issues found",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "SpotBugs Analysis",
                    False,
                    f"Code issues found: {result.stderr}",
                    time.time() - start_time
                ))
        except Exception as e:
            self.add_result(TestResult(
                "SpotBugs Analysis",
                False,
                f"Error running SpotBugs: {str(e)}",
                time.time() - start_time
            ))
        
        return True
    
    def test_artifacts(self) -> bool:
        """Test build artifacts"""
        self._print_status("Testing build artifacts...")
        
        # Test JAR file
        start_time = time.time()
        jar_path = Path("target/vaultscope-1.0.0.jar")
        if jar_path.exists():
            self.add_result(TestResult(
                "JAR Artifact",
                True,
                f"JAR file exists: {jar_path}",
                time.time() - start_time
            ))
        else:
            self.add_result(TestResult(
                "JAR Artifact",
                False,
                "JAR file not found",
                time.time() - start_time
            ))
            return False
        
        # Test runtime image
        start_time = time.time()
        runtime_path = Path("target/java-runtime")
        if runtime_path.exists():
            self.add_result(TestResult(
                "Runtime Image",
                True,
                f"Runtime image exists: {runtime_path}",
                time.time() - start_time
            ))
        else:
            self.add_result(TestResult(
                "Runtime Image",
                False,
                "Runtime image not found",
                time.time() - start_time
            ))
        
        # Test distribution artifacts
        start_time = time.time()
        dist_path = Path("target/dist")
        if dist_path.exists():
            artifacts = list(dist_path.glob("*"))
            if artifacts:
                self.add_result(TestResult(
                    "Distribution Artifacts",
                    True,
                    f"Found {len(artifacts)} distribution artifacts",
                    time.time() - start_time
                ))
            else:
                self.add_result(TestResult(
                    "Distribution Artifacts",
                    False,
                    "No distribution artifacts found",
                    time.time() - start_time
                ))
        else:
            self.add_result(TestResult(
                "Distribution Artifacts",
                False,
                "Distribution directory not found",
                time.time() - start_time
            ))
        
        return True
    
    def test_runtime_execution(self) -> bool:
        """Test runtime execution"""
        self._print_status("Testing runtime execution...")
        
        start_time = time.time()
        try:
            # Test JAR execution with version flag
            result = self._run_command([
                'java', '-Djava.awt.headless=true', 
                '-jar', 'target/vaultscope-1.0.0.jar', 
                '--version'
            ], timeout=30)
            
            if result.returncode == 0:
                self.add_result(TestResult(
                    "Runtime Execution",
                    True,
                    "Application runs successfully",
                    time.time() - start_time
                ))
                return True
            else:
                self.add_result(TestResult(
                    "Runtime Execution",
                    False,
                    f"Runtime execution failed: {result.stderr}",
                    time.time() - start_time
                ))
                return False
        except Exception as e:
            self.add_result(TestResult(
                "Runtime Execution",
                False,
                f"Error during runtime test: {str(e)}",
                time.time() - start_time
            ))
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_duration = time.time() - self.start_time
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = sum(1 for r in self.results if not r.passed)
        
        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "platform": self.platform_info,
                "java_version": self.java_version,
                "maven_version": self.maven_version,
                "total_duration": total_duration,
                "test_summary": {
                    "total_tests": len(self.results),
                    "passed": passed_tests,
                    "failed": failed_tests,
                    "success_rate": (passed_tests / len(self.results)) * 100 if self.results else 0
                }
            },
            "test_results": [
                {
                    "name": result.name,
                    "passed": result.passed,
                    "message": result.message,
                    "duration": result.duration,
                    "timestamp": result.timestamp.isoformat()
                }
                for result in self.results
            ]
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], filename: str = None):
        """Save test report to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._print_success(f"Test report saved to: {filename}")
    
    def print_summary(self):
        """Print test summary"""
        total_duration = time.time() - self.start_time
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = sum(1 for r in self.results if not r.passed)
        
        print(f"\n{Colors.BOLD}=== TEST SUMMARY ==={Colors.END}")
        print(f"Platform: {self.platform_info['system']} {self.platform_info['release']}")
        print(f"Java Version: {self.java_version}")
        print(f"Maven Version: {self.maven_version}")
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Total Tests: {len(self.results)}")
        print(f"{Colors.GREEN}Passed: {passed_tests}{Colors.END}")
        print(f"{Colors.RED}Failed: {failed_tests}{Colors.END}")
        
        if failed_tests == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✅ ALL TESTS PASSED!{Colors.END}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}❌ {failed_tests} TEST(S) FAILED!{Colors.END}")
            print(f"\nFailed tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  - {result.name}: {result.message}")
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        print(f"{Colors.BOLD}🛡️  VaultScope Enterprise Cross-Platform Test Suite{Colors.END}")
        print("=" * 60)
        
        # Run test suites
        tests = [
            ("Environment Setup", self.test_environment_setup),
            ("Build Process", self.test_build_process),
            ("Unit Tests", self.test_unit_tests),
            ("Integration Tests", self.test_integration_tests),
            ("Security Checks", self.test_security_checks),
            ("Build Artifacts", self.test_artifacts),
            ("Runtime Execution", self.test_runtime_execution)
        ]
        
        for test_name, test_func in tests:
            print(f"\n{Colors.CYAN}📋 {test_name}{Colors.END}")
            print("-" * 40)
            
            try:
                test_func()
            except Exception as e:
                self.add_result(TestResult(
                    test_name,
                    False,
                    f"Test suite failed: {str(e)}",
                    0
                ))
        
        # Generate and save report
        report = self.generate_report()
        self.save_report(report)
        
        # Print summary
        self.print_summary()
        
        # Return success status
        return all(result.passed for result in self.results)

def main():
    """Main entry point"""
    tester = CrossPlatformTester()
    
    try:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test execution interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()