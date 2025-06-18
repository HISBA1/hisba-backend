from .models import Rating

def calculate_weighted_rating(store):
    ratings = Rating.objects.filter(store=store)
    n = ratings.count()
    if n == 0:
        return 0

    weighted_sum = sum([rating.value * rating.weight for rating in ratings])
    weight_sum = sum([rating.weight for rating in ratings])

    weighted_average = weighted_sum / weight_sum

    correction_factor = 0.9 if n < 10 else 1.0
    final_rating = weighted_average * correction_factor

    return final_rating

import requests
import logging
from geopy.distance import geodesic

logger = logging.getLogger(__name__)

def get_coordinates(address):
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        "q": address,
        "format": "json"
    }
    response = requests.get(url, params=params)
    data = response.json()

    if data:
        # البحث عن النتيجة التي تكون `class` هي "place" و `type` هي "city"
        for result in data:
            if result.get("class") == "place" and result.get("type") == "city":
                return (result["lat"], result["lon"])
        
        # إذا لم نجد النتيجة المناسبة نختار أول نتيجة
        return (data[0]["lat"], data[0]["lon"])

    return (None, None)
def calculate_distance(coord1, coord2):
    return geodesic(coord1, coord2).kilometers

def calculate_delivery_fee(distance):
    base_fee = 5.00
    return base_fee + (distance * 0.50)