import {Schema,model} from "mongoose"

const TechEventsFormat = {
    EventTitle : {
        type:String,
        required:true
    },
    EventType:{
        type:String,
        required:true
    },
    Organizer:{
        type:String,
        required:true
    },
    OnlineorOffline:{
        type:String,
        required:true
    },
    PricePool:{
        type:String,
        required:false
    },
    OrganisationName:{
        type:String,
        required:true
    },
    City:{
        type:String,
        required:true
    },
    State:{
        type:String,
        required:true
    },
    Venue:{
        type:String,
        required:true
    },
    StartDate:{
        type:Date,
        required:true
    },
    EndDate:{
        type:Date,
        required:true
    },
    SpecifiedStacks:{
        type:String,
        required:true
    }
}

const TechEventsSchema = new Schema(TechEventsFormat)
export const TechEventsModel = model("TechEvents",TechEventsSchema)

