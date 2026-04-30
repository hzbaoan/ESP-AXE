import { NO_ERRORS_SCHEMA } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetworkComponent } from './network.component';

describe('NetworkComponent', () => {
  let component: NetworkComponent;
  let fixture: ComponentFixture<NetworkComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetworkComponent],
      schemas: [NO_ERRORS_SCHEMA]
    });
    TestBed.overrideComponent(NetworkComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(NetworkComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
