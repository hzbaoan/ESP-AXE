import { NO_ERRORS_SCHEMA } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { of } from 'rxjs';
import { ToastrService } from 'ngx-toastr';

import { EditComponent } from './edit.component';
import { ActivatedRoute } from '@angular/router';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';

describe('EditComponent', () => {
  let component: EditComponent;
  let fixture: ComponentFixture<EditComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [EditComponent],
      imports: [ReactiveFormsModule],
      providers: [
        LoadingService,
        { provide: ActivatedRoute, useValue: { queryParams: of({}) } },
        { provide: SystemService, useValue: jasmine.createSpyObj('SystemService', ['getInfo', 'updateSystem', 'restart']) },
        { provide: ToastrService, useValue: jasmine.createSpyObj('ToastrService', ['success', 'error']) }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    });
    TestBed.overrideComponent(EditComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(EditComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
