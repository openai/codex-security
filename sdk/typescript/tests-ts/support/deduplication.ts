import { rejecting } from "./errors.js";
export function emptyNeighborhoodReviewer() {
  return {
    screen: rejecting("No review for an empty neighborhood"),
    reviewPair: rejecting("No pair to review"),
  };
}
