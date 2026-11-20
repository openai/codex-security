import sys
from multiprocessing import get_context

from gateway import submit
from worker import import_next


if __name__ == "__main__":
    context = get_context("spawn")
    jobs = context.Queue()
    try:
        submit(sys.stdin.buffer.read(), jobs)
        consumer = context.Process(target=import_next, args=(jobs,))
        consumer.start()
        consumer.join()
        sys.exit(consumer.exitcode)
    finally:
        jobs.cancel_join_thread()
        jobs.close()
