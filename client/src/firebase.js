import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
    apiKey: "AIzaSyCXly84h35DX9tD7kPxCVI9cnRn5OOAGdE",
    authDomain: "linkshield-c7fec.firebaseapp.com",
    projectId: "linkshield-c7fec",
    storageBucket: "linkshield-c7fec.firebasestorage.app",
    messagingSenderId: "543856516877",
    appId: "1:543856516877:web:957062eb0778bb18ed5a44",
    measurementId: "G-NQHZHX9YM1"
  };
const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);