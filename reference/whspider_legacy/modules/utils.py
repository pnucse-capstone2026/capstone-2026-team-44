import threading
import time
import sys

class DotsSpinner:
    def __init__(self, message="크롤링 중"):
        self.message = message
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.start()
    def _animate(self):
        dot_cycle = ["", ".", "..", "..."]
        i = 0
        while self.running:
            sys.stdout.write(f"\r{self.message}{dot_cycle[i % len(dot_cycle)]}   ")
            sys.stdout.flush()
            time.sleep(0.4)
            i += 1

    def stop(self):
        self.running = False
        self.thread.join()
        sys.stdout.write("\r크롤링 완료!            \n")
        sys.stdout.flush()
