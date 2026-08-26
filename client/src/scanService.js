import {
    collection,
    addDoc,
    serverTimestamp,
  } from "firebase/firestore";
  
  import { db } from "./firebase";
  
  export const saveScan = async ({
    userId,
    url,
    result,
    riskScore = null,
  }) => {
    if (!userId) {
      throw new Error("No user logged in. Scan was not saved.");
    }
  
    try {
      const siteName =
        result?.siteName ||
        result?.title ||
        (() => {
          try {
            const normalizedUrl = /^https?:\/\//i.test(url)
              ? url
              : `https://${url}`;
  
            return new URL(normalizedUrl).hostname.replace(
              /^www\./i,
              ""
            );
          } catch {
            return "Unknown website";
          }
        })();
  
      const scanData = {
        userId,
        url,
        result,
        riskScore,
        level: result?.level || "UNKNOWN",
        siteName,
        createdAt: serverTimestamp(),
      };
  
      const docRef = await addDoc(
        collection(db, "scans"),
        scanData
      );
  
      return {
        id: docRef.id,
        data: {
          ...scanData,
          createdAt: new Date(),
        },
      };
    } catch (error) {
      console.error("Error saving scan:", error);
      throw error;
    }
  };
  