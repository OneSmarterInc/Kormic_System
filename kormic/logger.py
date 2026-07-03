import logging
import os
from datetime import datetime

class KormicLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # We use standard logging for file output, and can expose a method for rich console if needed
        self.logger = logging.getLogger("kormic_system")
        self.logger.setLevel(logging.DEBUG)
        
        # Avoid duplicate handlers if reloaded
        if not self.logger.handlers:
            log_file = os.path.join(self.log_dir, f"system_runtime_{datetime.now().strftime('%Y%m%d')}.log")
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            
            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(agent_code)s] [%(phase)s] - %(message)s'
            )
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def log(self, phase, agent_code, message, level=logging.INFO):
        """
        Logs a message with specific context.
        Phases: REGISTRATION, BIRTH, HISTORY, VERIFY, COMMUNICATE, MONITOR, SPAWN, INTERACT
        """
        extra = {'agent_code': agent_code, 'phase': phase}
        self.logger.log(level, message, extra=extra)
        
    def info(self, phase, agent_code, message):
        self.log(phase, agent_code, message, logging.INFO)

    def warning(self, phase, agent_code, message):
        self.log(phase, agent_code, message, logging.WARNING)

    def error(self, phase, agent_code, message):
        self.log(phase, agent_code, message, logging.ERROR)

# Global singleton instance
kormic_logger = KormicLogger()
