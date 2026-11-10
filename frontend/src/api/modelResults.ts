import type { ModelResults } from "../types";
import type { ApiRequester } from "./types";

export function fetchModelResults(
  apiRequest: ApiRequester,
  authToken: string,
): Promise<ModelResults> {
  return apiRequest<ModelResults>("/model/results", authToken);
}
