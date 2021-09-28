import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { HistoryLockComponent } from './history-lock.component';

describe('HistoryLockComponent', () => {
  let component: HistoryLockComponent;
  let fixture: ComponentFixture<HistoryLockComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ HistoryLockComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(HistoryLockComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
