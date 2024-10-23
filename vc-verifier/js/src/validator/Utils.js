export const getId = (obj) => {

    if (typeof obj === 'string') {
        return obj;
    }
    if (obj === null || obj === undefined) {
        return;
    }

    if (!('id' in obj)) {
        return;
    }

    return obj.id;
};

export const isValidURI = (id) => {
    try {
        const uri = new URL(id);
        return (uri.protocol === "did:") || (uri.protocol && uri.hostname);
    } catch {
        return false;
    }
};

export const isObject = (value) => {
    return (typeof value === 'object' && value !== null)
}


export const isNotNullOrEmpty = (value) => {
    return value !== null && value !== '' ;
}


export const isEmptyStringOrEmptyObject = (input) => {
    return input === "" || (typeof input === "object" && Object.keys(input).length === 0);
}