FROM node:12.11.0-alpine AS builder
WORKDIR /dash
COPY dash /dash

RUN npm config set unsafe-perm true
RUN npm install npm@latest -g
RUN npm install --save-dev @angular-devkit/build-angular
# RUN npm i yarn@latest -g --force
RUN yarn global add @angular/cli@11.2.0

RUN ng build --prod

EXPOSE 4200
CMD ng serve --host 0.0.0.0 --disableHostCheck true

