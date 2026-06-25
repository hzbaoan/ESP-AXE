import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule } from '@angular/common/http/testing';

import { GithubUpdateService } from './github-update.service';

describe('GithubUpdateService', () => {
  let service: GithubUpdateService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule]
    });
    service = TestBed.inject(GithubUpdateService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
