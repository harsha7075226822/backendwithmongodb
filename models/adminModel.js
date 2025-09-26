import {Schema,model} from "mongoose"

const adminSchemaFormat = {
    email:{
        type:String,
        required:true,
        unique:true
    },
    code:{
        type:String,
        required:true
    }
}

const AdminSchema = new Schema(adminSchemaFormat)
export const AdminModel = model("admindetails",AdminSchema)