import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { inject } from '@angular/core';
import { Observable, map, catchError, of } from 'rxjs';
import { SystemService } from '../services/system.service';

export const ApModeGuard: CanActivateFn = (): Observable<boolean | UrlTree> => {
  const systemService = inject(SystemService);
  const router = inject(Router);

  return systemService.getInfo().pipe(
    map(info => {
      if (info.provisioningRequired) {
        return router.createUrlTree(['/ap']);
      }
      return true;
    }),
    catchError(() => of(true))
  );
};
