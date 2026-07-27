import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.AQ.Ab8RN6KR_G_BOOSmNPZGCPXpgDVnZiK0qJeXAY3nsTS1BleQ0w,
});

const response = await ai.models.generateContent({
  model: "gemini-2.5-flash",
  contents: "Explain this repository.",
});

console.log(response.text);
pip install google-genai
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const response = await ai.models.generateContent({
  model: "gemini-2.5-flash",
  contents: "Explain this repository.",
});

console.log(response.text);
npm install @google/genai
