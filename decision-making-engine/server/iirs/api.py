from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
import requests, json
import re
from envs.cns_toy_env import CyberNetSecToyEnv
from core.renderer import SocketRenderer
from signature import prepareAsyncMessage
from envs.cns_toy_env_data import init_data

import pytz
from datetime import datetime

import subprocess

from multiprocessing import Process as process
from multiprocessing import Manager
from multiprocessing.managers import BaseManager
import multiprocessing as mp
import logging
import os
from core.api_state import state
from core.callable_main import main
from utils.helpers import getAllactions
import subprocess
import socket
import psutil, signal
from multiprocessing import Process as process, Lock, Semaphore
import freeport
import stomp

APP = Flask(__name__)
api = Api(app = APP)

def isOpen(ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip, int(port)))
      s.shutdown(2)
      return True
   except:
    return False

BaseManager.register('state', state)
manager = BaseManager()
manager.start()
currentState = manager.state()

def kill_pid_and_all_children(pid_to_kill):
  try:
    parent_proc = psutil.Process(pid_to_kill)
  except psutil.NoSuchProcess:
    return
  children = parent_proc.children(recursive=True)
  for child_proc in children:
    child_proc.send_signal(signal.SIGTERM)
  parent_proc.send_signal(signal.SIGTERM)

global p1, new_renderer, env, sem
sem = Lock()

@APP.before_first_request
def start_routine():
    pass

class uploadTopology(Resource):
  def post(self):
    global p1, new_renderer, env, sem
    json_data = request.get_json(force=True)
    try:
      with open('tmp/attack_graph_received.json', 'w+') as fp:
        json.dump(json_data, fp)
        logging.info("Attack graph stored.")
    except Exception as error:
      logging.exception(error)
      pass
    
    try:
      while p1.is_alive():  
        try:
          kill_pid_and_all_children(p1.pid)
        except Exception:
          pass
      logging.info("Processes were successfully killed")
    except Exception as error:
      logging.exception(error)
      logging.error('IGNORE THIS, if iRE has just started.')

    try:
      new_renderer.close_server()
    except Exception as error:
      logging.exception(error)
      logging.error('IGNORE THIS, if iRE has just started.')

    logging.info("Acquiring Semaphore...")
    
    try:
      sem.acquire()
      new_renderer = SocketRenderer(sem)
      env = CyberNetSecToyEnv(new_renderer)
      p1 = process(
        target = main,
        args=(currentState, env, currentState.get_min_iteration(),currentState.get_tradeoff(),\
          currentState.get_max_processes()))  
      p1.start()
    except Exception as error:
      logging.exception(error)
    
    return 200

  def get(self):
    with open('tmp/attack_graph_received.json', 'r') as fp:
      topology = json.load(fp)
    return jsonify(topology)


class getDecision(Resource):
  def get(self):
    return prepareAsyncMessage(currentState.get_action()["payload"])

  def post(self):
    json_data = request.get_json(force=True)
    return 200

class parameters(Resource):
  def get(self):
    return prepareAsyncMessage(currentState.get_parameters()["payload"])
  
  def post(self):
    json_data = request.get_json(force=True)
    json_data = json_data["payload"]["ire"]
    if 'sp_tradeoff' in json_data.keys():
      grade = json_data['sp_tradeoff']
      currentState.set_sp(grade)
      logging.debug('[DEBUG] POST:/config sp_tradeoff = {0}'.format(grade))
    if 'sa_tradeoff' in json_data.keys():
      currentState.set_tradeoff(json_data['sa_tradeoff'])
      logging.debug('[DEBUG] POST:/config sa_tradeoff = {0}'.format(currentState.get_tradeoff()))
    if 'auto_mode' in json_data.keys():
      currentState.set_auto_mode(json_data['auto_mode'])
      logging.debug('[DEBUG] POST:/config auto_mode = {0}'.format(currentState.get_auto_mode()))
    return 200


class test(Resource):
  def get(self):
    payload = {
      "api": "3.0",
      "message": "iRE test response",
      "status": "OK"
    }
    return prepareAsyncMessage(payload)

  
class compromised(Resource):
  def get(self):
    return prepareAsyncMessage(currentState.get_compromised())

logging.basicConfig(level=logging.DEBUG)
rootLogger = logging.getLogger()

filename = 'ire'
fileHandler = logging.FileHandler("{0}/{1}.log".format('.', filename))
rootLogger.addHandler(fileHandler)

api.add_resource(compromised, "/compromised")
api.add_resource(test, "/test")
api.add_resource(uploadTopology, "/topology")
api.add_resource(getDecision, "/decision")
api.add_resource(parameters, "/config")
APP.run(port = 17891, debug=True, host = '0.0.0.0')
