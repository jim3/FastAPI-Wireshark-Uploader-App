import os
import pymongo
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict
from packets import get_packets

load_dotenv()

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# connect to MongoDB Atlas using .env for credentials and connection string
client = pymongo.MongoClient(os.getenv("MONGO_DB_CONNECTION_STRING"))

# getting the database
db = client.protocol_analyzer

# getting the collection
collection = db.protocols


# upload page for your json files
@app.get("/", response_class=HTMLResponse)
async def index():
    with open("templates/index.html", "r") as file:
        content = file.read()
    return content


# Define a Pydantic model for the packet data
class PacketResult(BaseModel):
    ip: List[str]
    mac: List[str]
    udp: List[str]
    tcp: List[str]
    http_requests: List[str]
    ssdp_requests: List[str]
    slsk_username: List[str]
    slsk_search_text: List[str]
    iplocation: List[str]


@app.post("/packets")
async def analyze_packets(packets: UploadFile = File(...)):
    # Analyze the packets and get the result
    result = get_packets(packets.filename)

    # Create a Pydantic model instance from the result dictionary
    packet_data = PacketResult(**result)

    # Insert the packet data into the database collection
    try:
        inserted_packet = collection.insert_one(packet_data.dict())
        print("Packet inserted:", inserted_packet.inserted_id)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Error inserting packet into the database.")

    # Return the analysis result as JSON response
    return JSONResponse(content=result)
