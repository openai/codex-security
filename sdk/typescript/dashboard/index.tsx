import "./styles.css";
import { createRoot } from "react-dom/client";
import { App } from "./App.js";

const theme = matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => {
  document.documentElement.dataset["theme"] = theme.matches ? "dark" : "light";
};
applyTheme();
theme.addEventListener("change", applyTheme);
createRoot(document.getElementById("root")!).render(<App />);
