import { NO_ERRORS_SCHEMA } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, Subject } from 'rxjs';

import { LogsComponent } from './logs.component';
import { SystemService } from 'src/app/services/system.service';
import { WebSocketService } from 'src/app/services/web-socket.service';

describe('LogsComponent', () => {
  let component: LogsComponent;
  let fixture: ComponentFixture<LogsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [LogsComponent],
      providers: [
        { provide: SystemService, useValue: { getInfo: () => of({}) } },
        { provide: WebSocketService, useValue: { ws$: new Subject<string>() } }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    }).compileComponents();
    TestBed.overrideComponent(LogsComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(LogsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
