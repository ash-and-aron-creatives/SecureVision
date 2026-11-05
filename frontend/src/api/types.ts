export type ApiRequester = <T>(
  path: string,
  authToken: string | null,
  init?: RequestInit,
) => Promise<T>;
