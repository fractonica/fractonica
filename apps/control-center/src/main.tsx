import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fractonica/ui/styles.css";
import App from "./App";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Control center root element was not found.");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
