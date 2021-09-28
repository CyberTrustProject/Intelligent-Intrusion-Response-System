import { Injectable } from '@angular/core';
import { Subject, Observable, BehaviorSubject } from 'rxjs';
import { scan, map, startWith } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class HistoryService {

  synchronized = true;

  private states = [];
  private beliefs = [];
  private plots = [];
  private alerts = [];

  private stateGraph = new Subject<string>();
  private beliefGraph = new Subject<string>();
  private plot = new Subject<string>();
  private alert = new Subject<Array<{ name: string, triggered: boolean}>>();

  private availableStates = new BehaviorSubject<number>(0);
  private availabeBeliefs = new BehaviorSubject<number>(0);
  private availabePlots = new BehaviorSubject<number>(0);
  private availabeAlerts = new BehaviorSubject<number>(0);

  private currentStateStep = new BehaviorSubject<number>(0);
  private currentBeliefStep = new BehaviorSubject<number>(0);
  private currentPlotStep = new BehaviorSubject<number>(0);
  private currentAlertStep = new BehaviorSubject<number>(0);

  constructor() {
  }

  storeState(state: string) {
    this.states.push(state);
    this.stateGraph.next(state);
    this.availableStates.next(this.availableStates.value + 1);
    this.currentStateStep.next(this.availableStates.value);
  }

  storeBelief(belief: string) {
    this.beliefs.push(belief);
    this.beliefGraph.next(belief);
    this.availabeBeliefs.next(this.availabeBeliefs.value + 1);
    this.currentBeliefStep.next(this.availabeBeliefs.value);
  }

  storePlot(plot: string) {
    this.plots.push(plot);
    this.plot.next(plot);
    this.availabePlots.next(this.availabePlots.value + 1);
    this.currentPlotStep.next(this.availabePlots.value);
  }

  storeAlert(alert: Array<{ name: string, triggered: boolean}>) {
    this.alerts.push(alert);
    this.alert.next(alert);
    this.availabeAlerts.next(this.availabeAlerts.value + 1);
    this.currentAlertStep.next(this.availabeAlerts.value);
  }

  get state() {
    return this.stateGraph.asObservable();
  }

  get belief() {
    return this.beliefGraph.asObservable();
  }

  get triggeredAlerts() {
    return this.alert.asObservable();
  }

  get stateCount() {
    return this.availableStates.asObservable();
  }

  get beliefCount() {
    return this.availabeBeliefs.asObservable();
  }

  get plotCount() {
    return this.availabePlots.asObservable();
  }

  get alertCount() {
    return this.availabeAlerts.asObservable();
  }

  get stateCurrentStep() {
    return this.currentStateStep.asObservable();
  }

  get beliefCurrentStep() {
    return this.currentBeliefStep.asObservable();
  }

  get plotCurrentStep() {
    return this.currentPlotStep.asObservable();
  }

  get alertCurrentStep() {
    return this.currentAlertStep.asObservable();
  }

  stateRecall(step: number) {
    this.stateGraph.next(this.states[step - 1]);
    this.currentStateStep.next(step);
    if (this.synchronized) {
      this.beliefGraph.next(this.beliefs[step - 1]);
      this.currentBeliefStep.next(step);
      this.plot.next(this.plots[step - 1]);
      this.currentPlotStep.next(step);
      this.currentAlertStep.next(step);
    }
  }

  beliefRecall(step: number) {
    this.beliefGraph.next(this.beliefs[step - 1]);
    this.currentBeliefStep.next(step);
    if (this.synchronized) {
      this.stateGraph.next(this.states[step - 1]);
      this.currentStateStep.next(step);
      this.plot.next(this.plots[step - 1]);
      this.currentPlotStep.next(step);
      this.currentAlertStep.next(step);
    }
  }

  plotRecall(step: number) {
    this.plot.next(this.plots[step - 1]);
    this.currentPlotStep.next(step);
    if (this.synchronized) {
      this.stateGraph.next(this.states[step - 1]);
      this.currentStateStep.next(step);
      this.beliefGraph.next(this.beliefs[step - 1]);
      this.currentBeliefStep.next(step);
      this.currentAlertStep.next(step);
    }
  }
}
